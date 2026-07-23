use std::collections::BTreeMap;

use itertools::Itertools;
use num_traits::Zero;
use tracing::instrument;

use crate::core::channel::{Channel, MerkleChannel};
use crate::core::fields::m31::BaseField;
use crate::core::fields::qm31::{SecureField, QM31};
use crate::core::fri::{
    ExtendedFriLayerProof, ExtendedFriProof, FriConfig, FriLayerProof, FriLayerProofAux, FriProof,
    FriProofAux,
};
use crate::core::poly::line::LinePoly;
use crate::core::queries::{draw_queries, Queries};
use crate::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use crate::core::vcs_lifted::verifier::LOG_PACKED_LEAF_SIZE;
use crate::prover::backend::{Col, ColumnOps};
use crate::prover::line::LineEvaluation;
use crate::prover::poly::circle::{PolyOps, SecureEvaluation};
use crate::prover::poly::twiddles::TwiddleTree;
use crate::prover::poly::BitReversedOrder;
use crate::prover::secure_column::SecureColumnByCoords;
use crate::prover::vcs_lifted::ops::MerkleOpsLifted;
use crate::prover::vcs_lifted::prover::MerkleProverLifted;

pub trait FriOps: ColumnOps<BaseField> + PolyOps + Sized + ColumnOps<SecureField> {
    /// Folds a degree `d` polynomial into a degree `d / 2^k` polynomial, where `k = alphas.len()`.
    ///
    /// For i ∈ [0, k), the i-th fold computes the evaluation of `f_{i+1} = f_{i,0} + alphas[i] *
    /// f_{i,1}` on `E_{i+1} = pi(E_i)`, where:
    /// * `f_i` is the folded polynomial at fold i (`f_0 = eval`), evaluated on line domain `E_i`
    ///   (`E_0 = eval.domain()`).
    /// * `pi(x) = 2x^2 - 1` is the doubling map.
    /// * `f_{i,0}` and `f_{i,1}` are the polynomials determined by the identity `2*f_i(x) =
    ///   f_{i,0}(pi(x)) + x * f_{i,1}(pi(x))`.
    ///
    /// # Panics
    ///
    /// Panics if `alphas` is empty.
    fn fold_line(
        eval: &LineEvaluation<Self>,
        alphas: &[SecureField],
        twiddles: &TwiddleTree<Self>,
    ) -> LineEvaluation<Self>;

    /// Folds and accumulates a degree `d` circle polynomial into a degree `d/2` univariate
    /// polynomial.
    ///
    /// Let `src` be the evaluation of a circle polynomial `f` on a
    /// [`CircleDomain`] `E`. This function computes evaluations of `f' = f0
    /// + alpha * f1` on the x-coordinates of `E` such that `2f(p) = f0(px) + py * f1(px)`. The
    /// evaluations of `f'` are accumulated into `dst` by the formula `dst = dst * alpha^2 + f'`.
    ///
    /// # Panics
    ///
    /// Panics if `src` is not double the length of `dst`.
    ///
    /// [`CircleDomain`]: crate::core::poly::circle::CircleDomain
    // TODO(andrew): Make folding factor generic.
    // TODO(andrew): Fold directly into FRI layer to prevent allocation.
    fn fold_circle_into_line(
        src: &SecureEvaluation<Self, BitReversedOrder>,
        alpha: SecureField,
        twiddles: &TwiddleTree<Self>,
    ) -> LineEvaluation<Self>;

    /// Decomposes a FRI-space polynomial into a polynomial inside the fft-space and the
    /// remainder term.
    /// FRI-space: polynomials of total degree n/2.
    /// Based on lemma #12 from the CircleStark paper: f(P) = g(P)+ lambda * alternating(P),
    /// where lambda is the cosset diff of eval, and g is a polynomial in the fft-space.
    fn decompose(
        eval: &SecureEvaluation<Self, BitReversedOrder>,
    ) -> (SecureEvaluation<Self, BitReversedOrder>, SecureField);
}

/// Computes `len` folding alphas derived by repeated squaring: `[alpha, alpha^2, alpha^4, ...]`.
pub fn squared_alpha_powers(alpha: SecureField, len: u32) -> Vec<SecureField> {
    let mut alphas = Vec::with_capacity(len as usize);
    let mut alpha = alpha;
    for _ in 0..len {
        alphas.push(alpha);
        alpha = alpha * alpha;
    }
    alphas
}

pub struct FriDecommitResult<H: MerkleHasherLifted> {
    pub fri_proof: ExtendedFriProof<H>,
    pub query_positions: Vec<usize>,
    pub unsorted_query_locations: Vec<usize>,
}

/// Read-only observation of committed inner FRI folds.
///
/// The callback runs after the layer root is mixed and its folding challenge is drawn, but before
/// the input evaluation is folded. The channel therefore exposes the exact live transcript state
/// at that boundary.
pub trait FriCommitObserver<B, MC>
where
    B: FriOps + MerkleOpsLifted<MC::H>,
    MC: MerkleChannel,
{
    fn observe_inner_fold(
        &mut self,
        _input: &LineEvaluation<B>,
        _folding_alpha: SecureField,
        _committed_root: <MC::H as MerkleHasherLifted>::Hash,
        _channel: &MC::C,
    ) {
    }
}

#[derive(Default)]
pub struct NoopFriCommitObserver;

impl<B, MC> FriCommitObserver<B, MC> for NoopFriCommitObserver
where
    B: FriOps + MerkleOpsLifted<MC::H>,
    MC: MerkleChannel,
{
}

/// A FRI prover that applies the FRI protocol to prove a set of polynomials are of low degree.
pub struct FriProver<'a, B: FriOps + MerkleOpsLifted<MC::H>, MC: MerkleChannel> {
    config: FriConfig,
    first_layer: FriFirstLayerProver<'a, B, MC::H>,
    inner_layers: Vec<FriInnerLayerProver<B, MC::H>>,
    last_layer_poly: LinePoly,
}
impl<'a, B: FriOps + MerkleOpsLifted<MC::H>, MC: MerkleChannel> FriProver<'a, B, MC> {
    /// Runs the commitment phase of FRI on one circle evaluation over a canonic circle domain.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// * The evaluation is not from a sufficiently low degree circle polynomial.
    /// * The evaluation domain is not a canonic circle domain.
    #[instrument(skip_all)]
    pub fn commit(
        channel: &mut MC::C,
        config: FriConfig,
        column: &'a SecureEvaluation<B, BitReversedOrder>,
        twiddles: &TwiddleTree<B>,
    ) -> Self {
        Self::commit_with_observer(
            channel,
            config,
            column,
            twiddles,
            &mut NoopFriCommitObserver,
        )
    }

    /// Runs the commitment phase while exposing each committed inner fold to `observer`.
    pub fn commit_with_observer<O: FriCommitObserver<B, MC> + ?Sized>(
        channel: &mut MC::C,
        config: FriConfig,
        column: &'a SecureEvaluation<B, BitReversedOrder>,
        twiddles: &TwiddleTree<B>,
        observer: &mut O,
    ) -> Self {
        assert!(column.domain.is_canonic(), "not canonic");

        let first_layer = Self::commit_first_layer(channel, &config, column);
        let (inner_layers, last_layer_evaluation) =
            Self::commit_inner_layers(channel, config, column, twiddles, observer);
        let last_layer_poly = Self::commit_last_layer(channel, config, last_layer_evaluation);

        Self {
            config,
            first_layer,
            inner_layers,
            last_layer_poly,
        }
    }

    /// Commits to the first FRI layer.
    fn commit_first_layer(
        channel: &mut MC::C,
        config: &FriConfig,
        column: &'a SecureEvaluation<B, BitReversedOrder>,
    ) -> FriFirstLayerProver<'a, B, MC::H> {
        // The circle-to-line fold is always equal to the config.fold_step.
        // TODO(Leo): consider support for smaller steps.
        let layer = FriFirstLayerProver::new(column, config.fold_step);
        MC::mix_root(channel, layer.merkle_tree.root());
        layer
    }

    /// Builds and commits to the inner FRI layers (all layers except the first and last).
    ///
    /// Returns all inner layers and the evaluation of the last layer.
    fn commit_inner_layers<O: FriCommitObserver<B, MC> + ?Sized>(
        channel: &mut MC::C,
        config: FriConfig,
        column: &SecureEvaluation<B, BitReversedOrder>,
        twiddles: &TwiddleTree<B>,
        observer: &mut O,
    ) -> (Vec<FriInnerLayerProver<B, MC::H>>, LineEvaluation<B>) {
        let mut layers = Vec::new();
        let folding_alpha = channel.draw_secure_felt();

        let mut layer_evaluation = B::fold_circle_into_line(column, folding_alpha, twiddles);
        let mut line_log_size = layer_evaluation.domain().log_size();

        // Apply any additional line folds requested for the first stage.
        if config.fold_step > 1 {
            let extra_line_folds = config.fold_step - 1;
            let alpha_sq_powers =
                squared_alpha_powers(folding_alpha * folding_alpha, extra_line_folds);
            layer_evaluation = B::fold_line(&layer_evaluation, &alpha_sq_powers, twiddles);
            line_log_size -= extra_line_folds;
        }

        let last_layer_log_domain_size = config.last_layer_domain_size().ilog2();
        assert!(
            line_log_size >= last_layer_log_domain_size,
            "The circle-to-line fold results in a smaller line domain than the last layer."
        );
        // If we're already at the last layer, there are no inner layers to compute.
        if line_log_size == last_layer_log_domain_size {
            return (layers, layer_evaluation);
        }
        // While we can, skip `config.fold_step` layers.
        while line_log_size > last_layer_log_domain_size + config.fold_step {
            let layer = FriInnerLayerProver::new(layer_evaluation, config.fold_step);
            let committed_root = layer.merkle_tree.root();
            MC::mix_root(channel, committed_root);
            let folding_alpha = channel.draw_secure_felt();
            observer.observe_inner_fold(&layer.evaluation, folding_alpha, committed_root, channel);
            let alpha_sq_powers = squared_alpha_powers(folding_alpha, config.fold_step);
            layer_evaluation = B::fold_line(&layer.evaluation, &alpha_sq_powers, twiddles);
            layers.push(layer);
            line_log_size -= config.fold_step;
        }

        // Do one last fold (of size 0 < k <= config.fold_step) to reach the correct size.
        let last_fold_step = line_log_size - last_layer_log_domain_size;
        let layer = FriInnerLayerProver::new(layer_evaluation, last_fold_step);
        let committed_root = layer.merkle_tree.root();
        MC::mix_root(channel, committed_root);
        let folding_alpha = channel.draw_secure_felt();
        observer.observe_inner_fold(&layer.evaluation, folding_alpha, committed_root, channel);
        let alpha_sq_powers = squared_alpha_powers(folding_alpha, last_fold_step);
        layer_evaluation = B::fold_line(&layer.evaluation, &alpha_sq_powers, twiddles);
        layers.push(layer);

        (layers, layer_evaluation)
    }

    /// Builds and commits to the last layer.
    ///
    /// The layer is committed to by sending the verifier all the coefficients of the remaining
    /// polynomial.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// * The evaluation domain size exceeds the maximum last layer domain size.
    /// * The evaluation is not of sufficiently low degree.
    fn commit_last_layer(
        channel: &mut MC::C,
        config: FriConfig,
        evaluation: LineEvaluation<B>,
    ) -> LinePoly {
        assert_eq!(evaluation.len(), config.last_layer_domain_size());

        let evaluation = evaluation.to_cpu();
        let mut coeffs = evaluation.interpolate().into_ordered_coefficients();

        let last_layer_degree_bound = 1 << config.log_last_layer_degree_bound;
        let zeros = coeffs.split_off(last_layer_degree_bound);
        assert!(zeros.iter().all(SecureField::is_zero), "invalid degree");

        let last_layer_poly = LinePoly::from_ordered_coefficients(coeffs);
        channel.mix_felts(&last_layer_poly);

        last_layer_poly
    }

    /// Returns a FRI proof and the query positions.
    pub fn decommit(self, channel: &mut MC::C) -> FriDecommitResult<MC::H> {
        let first_layer_log_size = self.first_layer.column.domain.log_size();
        let unsorted_query_locations =
            draw_queries(channel, first_layer_log_size, self.config.n_queries);
        let queries = Queries::new(&unsorted_query_locations, first_layer_log_size);

        let fri_proof = self.decommit_on_queries(&queries);
        FriDecommitResult {
            fri_proof,
            query_positions: queries.positions,
            unsorted_query_locations,
        }
    }

    /// # Panics
    ///
    /// Panics if the queries were sampled on the wrong domain size.
    pub fn decommit_on_queries(self, queries: &Queries) -> ExtendedFriProof<MC::H> {
        let Self {
            config,
            first_layer,
            inner_layers,
            last_layer_poly,
        } = self;

        let first_layer_proof = first_layer.decommit(queries, config.fold_step);

        let inner_layer_proofs = inner_layers
            .into_iter()
            .scan(queries.fold(config.fold_step), |layer_queries, layer| {
                let fold_step = layer.fold_step;
                let layer_proof = layer.decommit(layer_queries);
                *layer_queries = layer_queries.fold(fold_step);
                Some(layer_proof)
            })
            .collect_vec();

        let (inner_proofs, inner_layers_aux): (Vec<_>, Vec<_>) = inner_layer_proofs
            .into_iter()
            .map(|p| (p.proof, p.aux))
            .unzip();

        ExtendedFriProof {
            proof: FriProof {
                first_layer: first_layer_proof.proof,
                inner_layers: inner_proofs,
                last_layer_poly,
            },
            aux: FriProofAux {
                first_layer: first_layer_proof.aux,
                inner_layers: inner_layers_aux,
            },
        }
    }
}

/// Commitment to the first FRI layer.
struct FriFirstLayerProver<'a, B: FriOps + MerkleOpsLifted<H>, H: MerkleHasherLifted> {
    column: &'a SecureEvaluation<B, BitReversedOrder>,
    merkle_tree: MerkleProverLifted<B, H>,
    pack_leaves: bool,
}

impl<'a, B: FriOps + MerkleOpsLifted<H>, H: MerkleHasherLifted> FriFirstLayerProver<'a, B, H> {
    fn new(first_layer_column: &'a SecureEvaluation<B, BitReversedOrder>, fold_step: u32) -> Self {
        let pack_leaves =
            first_layer_column.values.len().ilog2() >= LOG_PACKED_LEAF_SIZE && fold_step > 1;
        let log_rows_per_leaf = if pack_leaves { LOG_PACKED_LEAF_SIZE } else { 0 };
        let merkle_tree = MerkleProverLifted::commit(
            first_layer_column.values.columns.iter().collect_vec(),
            first_layer_column.values.len().ilog2() - log_rows_per_leaf,
            log_rows_per_leaf,
        );

        FriFirstLayerProver {
            column: first_layer_column,
            merkle_tree,
            pack_leaves,
        }
    }

    fn decommit(self, queries: &Queries, fold_step: u32) -> ExtendedFriLayerProof<H> {
        assert_eq!(queries.log_domain_size, self.column.domain.log_size());

        let (decommitment_positions, column_witness, value_map) =
            compute_decommitment_positions_and_witness_evals(
                self.column,
                &queries.positions,
                fold_step,
            );

        let decommitment_positions = if self.pack_leaves {
            decommitment_positions
                .iter()
                .map(|position| position >> LOG_PACKED_LEAF_SIZE)
                .dedup()
                .collect_vec()
        } else {
            decommitment_positions
        };
        // We can pass an empty vector to the merkle decommit because we don't use its returned
        // opened values.
        // TODO(Leo): consider adding a method to merkle prover to decommit only the auth paths.
        let (_, decommitment) = self
            .merkle_tree
            .decommit(&decommitment_positions, Vec::<&Col<B, BaseField>>::new());
        let commitment = self.merkle_tree.root();

        ExtendedFriLayerProof {
            proof: FriLayerProof {
                fri_witness: column_witness,
                decommitment: decommitment.decommitment,
                commitment,
            },
            aux: FriLayerProofAux {
                all_values: vec![value_map],
                decommitment: decommitment.aux,
            },
        }
    }
}

/// A FRI layer comprises of a merkle tree that commits to evaluations of a polynomial.
///
/// The polynomial evaluations are viewed as evaluation of a polynomial on multiple distinct cosets
/// of size two. Each leaf of the merkle tree commits to a single coset evaluation.
// TODO(andrew): Support different step sizes and update docs.
// TODO(andrew): The docs are wrong. Each leaf of the merkle tree commits to a single
// QM31 value. This is inefficient and should be changed.
struct FriInnerLayerProver<B: FriOps + MerkleOpsLifted<H>, H: MerkleHasherLifted> {
    evaluation: LineEvaluation<B>,
    merkle_tree: MerkleProverLifted<B, H>,
    fold_step: u32,
    pack_leaves: bool,
}

impl<B: FriOps + MerkleOpsLifted<H>, H: MerkleHasherLifted> FriInnerLayerProver<B, H> {
    fn new(evaluation: LineEvaluation<B>, fold_step: u32) -> Self {
        let pack_leaves = evaluation.values.len().ilog2() >= LOG_PACKED_LEAF_SIZE && fold_step > 1;
        let log_rows_per_leaf = if pack_leaves { LOG_PACKED_LEAF_SIZE } else { 0 };
        let merkle_tree = MerkleProverLifted::commit(
            evaluation.values.columns.iter().collect_vec(),
            evaluation.values.len().ilog2() - log_rows_per_leaf,
            log_rows_per_leaf,
        );

        FriInnerLayerProver {
            evaluation,
            merkle_tree,
            fold_step,
            pack_leaves,
        }
    }

    fn decommit(self, queries: &Queries) -> ExtendedFriLayerProof<H> {
        let (decommitment_positions, fri_witness, value_map) =
            compute_decommitment_positions_and_witness_evals(
                &self.evaluation.values,
                queries,
                self.fold_step,
            );

        let decommitment_positions = if self.pack_leaves {
            decommitment_positions
                .iter()
                .map(|position| position >> LOG_PACKED_LEAF_SIZE)
                .dedup()
                .collect_vec()
        } else {
            decommitment_positions
        };
        // We can pass an empty vector to the merkle decommit because we don't use its returned
        // opened values.
        let (_, decommitment) = self
            .merkle_tree
            .decommit(&decommitment_positions, Vec::<&Col<B, BaseField>>::new());
        let commitment = self.merkle_tree.root();

        ExtendedFriLayerProof {
            proof: FriLayerProof {
                fri_witness,
                decommitment: decommitment.decommitment,
                commitment,
            },
            aux: FriLayerProofAux {
                all_values: vec![value_map],
                decommitment: decommitment.aux,
            },
        }
    }
}

/// Returns a column's merkle tree decommitment positions and the evals the verifier can't
/// deduce from previous computations but requires for decommitment and folding.
///
/// Returns a map from leaf index to its value.
fn compute_decommitment_positions_and_witness_evals(
    column: &SecureColumnByCoords<impl PolyOps>,
    query_positions: &[usize],
    fold_step: u32,
) -> (Vec<usize>, Vec<QM31>, BTreeMap<usize, QM31>) {
    let mut decommitment_positions = Vec::new();
    let mut witness_evals = Vec::new();
    let mut value_map = BTreeMap::new();

    // Group queries by the folding coset they reside in.
    for subset_queries in query_positions.chunk_by(|a, b| a >> fold_step == b >> fold_step) {
        let subset_start = (subset_queries[0] >> fold_step) << fold_step;
        let subset_decommitment_positions = subset_start..subset_start + (1 << fold_step);
        let mut subset_queries_iter = subset_queries.iter().peekable();

        for position in subset_decommitment_positions {
            // Add decommitment position.
            decommitment_positions.push(position);

            let eval = column.at(position);
            value_map.insert(position, eval);

            // Only add evals the verifier can't calculate.
            if subset_queries_iter.next_if_eq(&&position).is_none() {
                witness_evals.push(eval);
            }
        }
    }

    (decommitment_positions, witness_evals, value_map)
}

#[cfg(test)]
mod tests {

    use num_traits::One;

    use crate::core::channel::{Blake2sChannel, Channel, MerkleChannel};
    use crate::core::circle::{CirclePointIndex, Coset};
    use crate::core::fields::m31::{BaseField, P};
    use crate::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
    use crate::core::fri::FriConfig;
    use crate::core::poly::circle::CircleDomain;
    use crate::core::queries::Queries;
    use crate::core::test_utils::test_channel;
    use crate::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasher};
    use crate::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
    use crate::core::vcs_lifted::verifier::PACKED_LEAF_SIZE;
    use crate::prover::backend::cpu::CpuCirclePoly;
    use crate::prover::backend::simd::SimdBackend;
    use crate::prover::backend::{Col, Column, CpuBackend};
    use crate::prover::poly::circle::{PolyOps, SecureEvaluation};
    use crate::prover::poly::BitReversedOrder;
    use crate::prover::secure_column::SecureColumnByCoords;
    use crate::prover::vcs_lifted::ops::PackLeavesOps;

    /// Default blowup factor used for tests.
    const LOG_BLOWUP_FACTOR: u32 = 2;

    type FriProver<'a> = super::FriProver<'a, CpuBackend, Blake2sMerkleChannel>;

    #[derive(Default)]
    struct RecordingObserver {
        folds: Vec<(u32, SecureField, Blake2sHash, Blake2sHash, u32)>,
    }

    impl super::FriCommitObserver<CpuBackend, Blake2sMerkleChannel> for RecordingObserver {
        fn observe_inner_fold(
            &mut self,
            input: &crate::prover::line::LineEvaluation<CpuBackend>,
            folding_alpha: SecureField,
            committed_root: Blake2sHash,
            channel: &Blake2sChannel,
        ) {
            self.folds.push((
                input.domain().log_size(),
                folding_alpha,
                committed_root,
                channel.digest(),
                channel.n_draws(),
            ));
        }
    }

    #[derive(Clone)]
    struct SimdObservedFold {
        input: crate::prover::line::LineEvaluation<CpuBackend>,
        alpha: SecureField,
        root: Blake2sHash,
        digest: Blake2sHash,
        n_draws: u32,
    }

    #[derive(Default)]
    struct SimdRecordingObserver {
        folds: Vec<SimdObservedFold>,
    }

    impl super::FriCommitObserver<SimdBackend, Blake2sMerkleChannel> for SimdRecordingObserver {
        fn observe_inner_fold(
            &mut self,
            input: &crate::prover::line::LineEvaluation<SimdBackend>,
            alpha: SecureField,
            root: Blake2sHash,
            channel: &Blake2sChannel,
        ) {
            self.folds.push(SimdObservedFold {
                input: input.to_cpu(),
                alpha,
                root,
                digest: channel.digest(),
                n_draws: channel.n_draws(),
            });
        }
    }

    fn packed_blake_root(
        evaluation: &crate::prover::line::LineEvaluation<CpuBackend>,
    ) -> Blake2sHash {
        assert!(evaluation.len() >= PACKED_LEAF_SIZE);
        let mut layer = (0..evaluation.len() / PACKED_LEAF_SIZE)
            .map(|packed_row| {
                let mut hasher = Blake2sHasher::new();
                for offset in 0..PACKED_LEAF_SIZE {
                    for coord in 0..SECURE_EXTENSION_DEGREE {
                        hasher.update(
                            &evaluation.values.columns[coord]
                                [packed_row * PACKED_LEAF_SIZE + offset]
                                .0
                                .to_le_bytes(),
                        );
                    }
                }
                hasher.finalize()
            })
            .collect::<Vec<_>>();
        while layer.len() > 1 {
            layer = layer
                .chunks_exact(2)
                .map(|pair| Blake2sHasher::concat_and_hash(&pair[0], &pair[1]))
                .collect();
        }
        layer[0]
    }

    fn draw_secure_felt_from_digest(digest: Blake2sHash) -> (SecureField, u32) {
        for counter in 0u32.. {
            let mut input = digest.0.to_vec();
            input.extend_from_slice(&counter.to_le_bytes());
            input.push(0);
            let hash = Blake2sHasher::hash(&input);
            let words = hash
                .0
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            if words.iter().all(|word| *word < 2 * P) {
                return (
                    SecureField::from_m31_array(core::array::from_fn(|i| {
                        BaseField::reduce(words[i] as u64)
                    })),
                    counter + 1,
                );
            }
        }
        unreachable!()
    }

    fn line_bytes(evaluation: &crate::prover::line::LineEvaluation<CpuBackend>) -> Vec<u8> {
        evaluation
            .values
            .into_iter()
            .flat_map(|value| value.to_m31_array())
            .flat_map(|value| value.0.to_le_bytes())
            .collect()
    }

    fn transcript_transition_is_valid(
        previous: &SimdObservedFold,
        next: &SimdObservedFold,
    ) -> bool {
        if packed_blake_root(&next.input) != next.root {
            return false;
        }
        let digest = Blake2sHasher::concat_and_hash(&previous.digest, &next.root);
        let (alpha, n_draws) = draw_secure_felt_from_digest(digest);
        digest == next.digest && alpha == next.alpha && n_draws == next.n_draws
    }

    fn round6_pair_is_valid(
        previous: &SimdObservedFold,
        round6: &SimdObservedFold,
        round3: &SimdObservedFold,
        twiddles: &crate::prover::poly::twiddles::TwiddleTree<CpuBackend>,
    ) -> bool {
        if previous.input.domain().log_size() != 9
            || round6.input.domain().log_size() != 6
            || round3.input.domain().log_size() != 3
            || !transcript_transition_is_valid(previous, round6)
            || !transcript_transition_is_valid(round6, round3)
        {
            return false;
        }
        let alpha2 = round6.alpha * round6.alpha;
        let folded = <CpuBackend as super::FriOps>::fold_line(
            &round6.input,
            &[round6.alpha, alpha2, alpha2 * alpha2],
            twiddles,
        );
        folded.values.to_vec() == round3.input.values.to_vec()
            && line_bytes(&folded) == line_bytes(&round3.input)
    }

    #[test]
    #[should_panic = "invalid degree"]
    fn committing_high_degree_polynomial_fails() {
        const LOG_EXPECTED_BLOWUP_FACTOR: u32 = LOG_BLOWUP_FACTOR;
        const LOG_INVALID_BLOWUP_FACTOR: u32 = LOG_BLOWUP_FACTOR - 1;
        let config = FriConfig::new(2, LOG_EXPECTED_BLOWUP_FACTOR, 3, 1);
        let column = polynomial_evaluation(6, LOG_INVALID_BLOWUP_FACTOR);
        let twiddles = CpuBackend::precompute_twiddles(column.domain.half_coset);

        FriProver::commit(&mut test_channel(), config, &column, &twiddles);
    }

    #[test]
    #[should_panic = "not canonic"]
    fn committing_column_from_invalid_domain_fails() {
        let invalid_domain = CircleDomain::new(Coset::new(CirclePointIndex::generator(), 3));
        assert!(!invalid_domain.is_canonic(), "must be an invalid domain");
        let config = FriConfig::new(2, 2, 3, 1);
        let column = SecureEvaluation::new(
            invalid_domain,
            [SecureField::one(); 1 << 4].into_iter().collect(),
        );
        let twiddles = CpuBackend::precompute_twiddles(column.domain.half_coset);

        FriProver::commit(&mut test_channel(), config, &column, &twiddles);
    }

    /// Returns an evaluation of a random polynomial with degree `2^log_degree`.
    ///
    /// The evaluation domain size is `2^(log_degree + log_blowup_factor)`.
    fn polynomial_evaluation(
        log_degree: u32,
        log_blowup_factor: u32,
    ) -> SecureEvaluation<CpuBackend, BitReversedOrder> {
        let poly = CpuCirclePoly::new(vec![BaseField::one(); 1 << log_degree]);
        let coset = Coset::half_odds(log_degree + log_blowup_factor - 1);
        let domain = CircleDomain::new(coset);
        let values = poly.evaluate(domain);
        SecureEvaluation::new(domain, values.into_iter().map(SecureField::from).collect())
    }

    #[test]
    fn test_fri_commit_decommit_with_jumps() {
        let config = FriConfig::new(2, LOG_BLOWUP_FACTOR, 3, 2);
        let column = polynomial_evaluation(6, LOG_BLOWUP_FACTOR);
        let twiddles = CpuBackend::precompute_twiddles(column.domain.half_coset);

        let prover = FriProver::commit(&mut test_channel(), config, &column, &twiddles);
        let queries = Queries::from_positions(vec![0, 3], 6 + LOG_BLOWUP_FACTOR);
        prover.decommit_on_queries(&queries);
    }

    #[test]
    fn observer_reports_inner_folds_in_transcript_order() {
        let config = FriConfig::new(2, LOG_BLOWUP_FACTOR, 3, 2);
        let column = polynomial_evaluation(8, LOG_BLOWUP_FACTOR);
        let twiddles = CpuBackend::precompute_twiddles(column.domain.half_coset);
        let mut channel = test_channel();
        let mut observer = RecordingObserver::default();

        let prover = FriProver::commit_with_observer(
            &mut channel,
            config,
            &column,
            &twiddles,
            &mut observer,
        );
        let proof = prover.decommit_on_queries(&Queries::from_positions(vec![0, 3], 10));

        assert_eq!(
            observer.folds.iter().map(|fold| fold.0).collect::<Vec<_>>(),
            [8, 6]
        );
        assert_eq!(observer.folds.len(), proof.proof.inner_layers.len());

        let mut replay = test_channel();
        Blake2sMerkleChannel::mix_root(&mut replay, proof.proof.first_layer.commitment);
        replay.draw_secure_felt();
        for (observed, layer) in observer.folds.iter().zip(&proof.proof.inner_layers) {
            Blake2sMerkleChannel::mix_root(&mut replay, layer.commitment);
            let alpha = replay.draw_secure_felt();
            assert_eq!(observed.1, alpha);
            assert_eq!(observed.2, layer.commitment);
            assert_eq!(observed.3, replay.digest());
            assert_eq!(observed.4, replay.n_draws());
        }
    }

    #[test]
    fn simd_observer_seals_exact_production_round6_boundary() {
        let config = FriConfig::new(0, 1, 70, 3);
        let cpu_column: SecureEvaluation<CpuBackend, BitReversedOrder> = {
            let poly =
                CpuCirclePoly::new((0..1 << 11).map(|i| BaseField::from(i * 17 + 29)).collect());
            let domain = CircleDomain::new(Coset::half_odds(11));
            let values = poly.evaluate(domain);
            SecureEvaluation::new(domain, values.into_iter().map(SecureField::from).collect())
        };
        let column = SecureEvaluation::new(
            cpu_column.domain,
            cpu_column.values.to_vec().into_iter().collect(),
        );
        let simd_twiddles = SimdBackend::precompute_twiddles(column.domain.half_coset);
        let cpu_twiddles = CpuBackend::precompute_twiddles(cpu_column.domain.half_coset);
        let mut observer = SimdRecordingObserver::default();

        super::FriProver::<'_, SimdBackend, Blake2sMerkleChannel>::commit_with_observer(
            &mut test_channel(),
            config,
            &column,
            &simd_twiddles,
            &mut observer,
        );

        let logs = observer
            .folds
            .iter()
            .map(|fold| fold.input.domain().log_size())
            .collect::<Vec<_>>();
        assert_eq!(logs, [9, 6, 3], "unexpected production callback order");
        let round6_positions = logs
            .windows(2)
            .enumerate()
            .filter_map(|(i, logs)| (logs == [6, 3]).then_some(i))
            .collect::<Vec<_>>();
        assert_eq!(round6_positions, [1], "round6 boundary must be unique");

        let [previous, round6, round3] = observer.folds.as_slice() else {
            panic!("production configuration must expose exactly three inner folds");
        };
        assert!(round6_pair_is_valid(
            previous,
            round6,
            round3,
            &cpu_twiddles
        ));

        let mut bad_round6_input = round6.clone();
        let changed = bad_round6_input.input.values.at(0) + SecureField::one();
        bad_round6_input.input.values.set(0, changed);
        assert!(!round6_pair_is_valid(
            previous,
            &bad_round6_input,
            round3,
            &cpu_twiddles
        ));

        let mut bad_round3_input = round3.clone();
        let changed = bad_round3_input.input.values.at(0) + SecureField::one();
        bad_round3_input.input.values.set(0, changed);
        assert!(!round6_pair_is_valid(
            previous,
            round6,
            &bad_round3_input,
            &cpu_twiddles
        ));

        let mut bad_root = round6.clone();
        bad_root.root.0[0] ^= 1;
        assert!(!round6_pair_is_valid(
            previous,
            &bad_root,
            round3,
            &cpu_twiddles
        ));

        let mut bad_alpha = round6.clone();
        bad_alpha.alpha += SecureField::one();
        assert!(!round6_pair_is_valid(
            previous,
            &bad_alpha,
            round3,
            &cpu_twiddles
        ));

        let mut bad_digest = round3.clone();
        bad_digest.digest.0[0] ^= 1;
        assert!(!round6_pair_is_valid(
            previous,
            round6,
            &bad_digest,
            &cpu_twiddles
        ));
    }

    #[test]
    fn noop_observer_preserves_fri_proof_bytes() {
        let config = FriConfig::new(2, LOG_BLOWUP_FACTOR, 3, 2);
        let column = polynomial_evaluation(8, LOG_BLOWUP_FACTOR);
        let twiddles = CpuBackend::precompute_twiddles(column.domain.half_coset);
        let queries = || Queries::from_positions(vec![0, 3], 10);

        let mut reference_channel = test_channel();
        let reference = FriProver::commit(&mut reference_channel, config, &column, &twiddles)
            .decommit_on_queries(&queries());

        let mut observed_channel = test_channel();
        let observed = FriProver::commit_with_observer(
            &mut observed_channel,
            config,
            &column,
            &twiddles,
            &mut super::NoopFriCommitObserver,
        )
        .decommit_on_queries(&queries());

        assert_eq!(
            serde_json::to_vec(&reference.proof).unwrap(),
            serde_json::to_vec(&observed.proof).unwrap()
        );
        assert_eq!(reference_channel.digest(), observed_channel.digest());
        assert_eq!(reference_channel.n_draws(), observed_channel.n_draws());
    }

    #[test]
    fn test_fri_commit_decommit_with_packed_leaves() {
        for fold_step in 2..=4 {
            let config = FriConfig::new(2, LOG_BLOWUP_FACTOR, 3, fold_step);
            let column = polynomial_evaluation(8, LOG_BLOWUP_FACTOR);
            let twiddles = CpuBackend::precompute_twiddles(column.domain.half_coset);

            let prover = FriProver::commit(&mut test_channel(), config, &column, &twiddles);
            let queries = Queries::from_positions(vec![1, 6, 11], 8 + LOG_BLOWUP_FACTOR);
            prover.decommit_on_queries(&queries);
        }
    }

    #[test]
    fn test_fri_commit_decommit_with_packed_leaves_simd() {
        for fold_step in 2..=4 {
            let config = FriConfig::new(2, LOG_BLOWUP_FACTOR, 3, fold_step);
            let cpu_eval = polynomial_evaluation(8, LOG_BLOWUP_FACTOR);
            let column = SecureEvaluation::new(
                cpu_eval.domain,
                cpu_eval.values.to_vec().into_iter().collect(),
            );
            let twiddles = SimdBackend::precompute_twiddles(column.domain.half_coset);
            let prover = super::FriProver::<'_, SimdBackend, Blake2sMerkleChannel>::commit(
                &mut test_channel(),
                config,
                &column,
                &twiddles,
            );
            let queries = Queries::from_positions(vec![1, 6, 11], 8 + LOG_BLOWUP_FACTOR);
            prover.decommit_on_queries(&queries);
        }
    }

    #[test]
    fn test_fri_commit_decommit_keccak256_cpu() {
        use crate::core::channel::Keccak256Channel;
        use crate::core::vcs_lifted::keccak256_merkle::Keccak256MerkleChannel;

        let config = FriConfig::new(2, LOG_BLOWUP_FACTOR, 3, 2);
        let column = polynomial_evaluation(6, LOG_BLOWUP_FACTOR);
        let twiddles = CpuBackend::precompute_twiddles(column.domain.half_coset);

        let prover = super::FriProver::<'_, CpuBackend, Keccak256MerkleChannel>::commit(
            &mut Keccak256Channel::default(),
            config,
            &column,
            &twiddles,
        );
        let queries = Queries::from_positions(vec![0, 3], 6 + LOG_BLOWUP_FACTOR);
        prover.decommit_on_queries(&queries);
    }

    #[test]
    fn test_fri_commit_decommit_keccak256_simd() {
        use crate::core::channel::Keccak256Channel;
        use crate::core::vcs_lifted::keccak256_merkle::Keccak256MerkleChannel;

        let config = FriConfig::new(2, LOG_BLOWUP_FACTOR, 3, 2);
        let cpu_eval = polynomial_evaluation(8, LOG_BLOWUP_FACTOR);
        let column = SecureEvaluation::new(
            cpu_eval.domain,
            cpu_eval.values.to_vec().into_iter().collect(),
        );
        let twiddles = SimdBackend::precompute_twiddles(column.domain.half_coset);
        let prover = super::FriProver::<'_, SimdBackend, Keccak256MerkleChannel>::commit(
            &mut Keccak256Channel::default(),
            config,
            &column,
            &twiddles,
        );
        let queries = Queries::from_positions(vec![1, 6, 11], 8 + LOG_BLOWUP_FACTOR);
        prover.decommit_on_queries(&queries);
    }

    #[test]
    fn test_pack_leaves_input_simd_matches_cpu() {
        for log_size in 2..8 {
            let values = (0..1 << log_size).map(|i| {
                SecureField::from_m31_array(core::array::from_fn(|coord| {
                    BaseField::from_u32_unchecked((i * SECURE_EXTENSION_DEGREE + coord) as u32)
                }))
            });
            let values = SecureColumnByCoords::<SimdBackend>::from_iter(values);

            let cpu_values = values.to_cpu();
            let cpu_cols: [&Col<CpuBackend, BaseField>; SECURE_EXTENSION_DEGREE] =
                core::array::from_fn(|i| &cpu_values.columns[i]);
            let generic: [Col<CpuBackend, BaseField>; SECURE_EXTENSION_DEGREE * PACKED_LEAF_SIZE] =
                <CpuBackend as PackLeavesOps>::pack_leaves_input(&cpu_cols);
            let simd_cols: [&Col<SimdBackend, BaseField>; SECURE_EXTENSION_DEGREE] =
                core::array::from_fn(|i| &values.columns[i]);
            let simd: [Col<SimdBackend, BaseField>; SECURE_EXTENSION_DEGREE * PACKED_LEAF_SIZE] =
                <SimdBackend as PackLeavesOps>::pack_leaves_input(&simd_cols);

            for col in 0..SECURE_EXTENSION_DEGREE * PACKED_LEAF_SIZE {
                assert_eq!(
                    generic[col].to_cpu(),
                    simd[col].to_cpu(),
                    "mismatch at log_size={log_size}, col={col}"
                );
            }
        }
    }
}
