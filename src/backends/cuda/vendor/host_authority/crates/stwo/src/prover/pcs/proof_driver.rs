//! Typed PCS/FRI proof-driver stages shared by backend orchestrators.
//!
//! The stage bodies below are the protocol implementation: both the reference
//! driver and backend-owned drivers sequence these same consuming states.  That
//! keeps transcript operations and proof/aux ordering in one place while still
//! making the orchestration boundary explicit enough for CUDA graph segments.

use itertools::Itertools;
use tracing::{span, Level};

use super::{
    compact_tree_columns, compact_tree_columns_cloned, decommit_compact_tree,
    print_column_size_histogram, CommitmentSchemeProver, CompactTreeColumns,
};
use crate::core::channel::{Channel, MerkleChannel};
use crate::core::circle::CirclePoint;
use crate::core::fields::m31::BaseField;
use crate::core::fields::qm31::SecureField;
use crate::core::fri::ExtendedFriProof;
use crate::core::pcs::quotients::{
    CommitmentSchemeProof, CommitmentSchemeProofAux, ExtendedCommitmentSchemeProof, PointSample,
};
use crate::core::pcs::utils::prepare_preprocessed_query_positions;
use crate::core::pcs::TreeVec;
use crate::core::poly::circle::CanonicCoset;
use crate::core::utils::MaybeOwned;
use crate::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use crate::core::ColumnVec;
use crate::prover::backend::BackendForChannel;
use crate::prover::fri::{FriCommitObserver, FriDecommitResult, FriProver, NoopFriCommitObserver};
use crate::prover::pcs::quotient_ops::{self, compute_fri_quotients};
use crate::prover::poly::circle::{CircleEvaluation, SecureEvaluation};
use crate::prover::poly::BitReversedOrder;

/// Stable protocol stages exposed to backend orchestration and telemetry.
///
/// The order is the channel order.  In particular, proof-of-work is mixed
/// before FRI queries are drawn; changing this order changes the transcript.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PcsProofStage {
    OodsEvaluation,
    QuotientAndCompaction,
    FriCommitAndFold,
    ProofOfWork,
    FriQueryAndDecommit,
    TreeDecommit,
    Assembly,
}

impl PcsProofStage {
    pub const ALL: [Self; 7] = [
        Self::OodsEvaluation,
        Self::QuotientAndCompaction,
        Self::FriCommitAndFold,
        Self::ProofOfWork,
        Self::FriQueryAndDecommit,
        Self::TreeDecommit,
        Self::Assembly,
    ];

    pub const fn index(self) -> usize {
        match self {
            Self::OodsEvaluation => 0,
            Self::QuotientAndCompaction => 1,
            Self::FriCommitAndFold => 2,
            Self::ProofOfWork => 3,
            Self::FriQueryAndDecommit => 4,
            Self::TreeDecommit => 5,
            Self::Assembly => 6,
        }
    }
}

/// Backend hook at typed proof-stage boundaries.
///
/// CUDA uses these calls for per-stage counters today and for explicit
/// context/arena graph segments next.  The hook deliberately receives no
/// implicit process or thread-local runtime state.
pub trait PcsProofStageObserver {
    fn stage_started(&mut self, _stage: PcsProofStage) {}
    fn stage_finished(&mut self, _stage: PcsProofStage) {}
}

#[derive(Default)]
pub struct NoopPcsProofStageObserver;

impl PcsProofStageObserver for NoopPcsProofStageObserver {}

struct PvtTimer {
    enabled: bool,
    last: std::time::Instant,
}

impl PvtTimer {
    fn new() -> Self {
        Self {
            enabled: std::env::var("STWO_PVT").as_deref() == Ok("1"),
            last: std::time::Instant::now(),
        }
    }

    fn mark(&mut self, label: &str) {
        if self.enabled {
            eprintln!("PVT {label} {:.3}", self.last.elapsed().as_secs_f64());
            self.last = std::time::Instant::now();
        }
    }
}

/// Initial state: committed trees plus the requested OODS points.
pub struct PcsOodsStage<'a, B: BackendForChannel<MC>, MC: MerkleChannel> {
    scheme: CommitmentSchemeProver<'a, B, MC>,
    sampled_points: TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
    timer: PvtTimer,
}

/// OODS values are in the transcript; the quotient challenge is next.
pub struct PcsQuotientStage<'a, B: BackendForChannel<MC>, MC: MerkleChannel> {
    scheme: CommitmentSchemeProver<'a, B, MC>,
    samples: TreeVec<Vec<Vec<PointSample>>>,
    sampled_values: TreeVec<ColumnVec<Vec<SecureField>>>,
    lifting_log_size: u32,
    timer: PvtTimer,
}

/// Quotient and diet compaction are complete; FRI commitment is next.
pub struct PcsFriStage<'a, B: BackendForChannel<MC>, MC: MerkleChannel> {
    scheme: CommitmentSchemeProver<'a, B, MC>,
    sampled_values: TreeVec<ColumnVec<Vec<SecureField>>>,
    compact_trees: Vec<Option<CompactTreeColumns<B>>>,
    quotients: SecureEvaluation<B, BitReversedOrder>,
    lifting_log_size: u32,
    timer: PvtTimer,
}

/// Scoped FRI-committed state.  It cannot escape [`PcsFriStage::with_fri_commit`]
/// because `FriProver` borrows the quotient evaluation through decommitment.
pub struct PcsFriCommittedStage<'q, 'a, B: BackendForChannel<MC>, MC: MerkleChannel> {
    scheme: CommitmentSchemeProver<'a, B, MC>,
    sampled_values: TreeVec<ColumnVec<Vec<SecureField>>>,
    compact_trees: Vec<Option<CompactTreeColumns<B>>>,
    fri_prover: FriProver<'q, B, MC>,
    lifting_log_size: u32,
    timer: PvtTimer,
}

/// FRI queries and proof are fixed; committed trace trees must now be opened.
pub struct PcsTreeDecommitStage<'a, B: BackendForChannel<MC>, MC: MerkleChannel> {
    scheme: CommitmentSchemeProver<'a, B, MC>,
    sampled_values: TreeVec<ColumnVec<Vec<SecureField>>>,
    compact_trees: Vec<Option<CompactTreeColumns<B>>>,
    lifting_log_size: u32,
    proof_of_work: u64,
    fri_proof: ExtendedFriProof<MC::H>,
    query_positions: Vec<usize>,
    unsorted_query_locations: Vec<usize>,
    timer: PvtTimer,
}

/// All protocol work is complete; only the stable proof/aux field ordering remains.
pub struct PcsAssemblyStage<H: MerkleHasherLifted> {
    proof: ExtendedCommitmentSchemeProof<H>,
}

impl<'a, B: BackendForChannel<MC>, MC: MerkleChannel> CommitmentSchemeProver<'a, B, MC> {
    pub fn begin_proof_driver(
        self,
        sampled_points: TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
    ) -> PcsOodsStage<'a, B, MC> {
        PcsOodsStage {
            scheme: self,
            sampled_points,
            timer: PvtTimer::new(),
        }
    }

    /// Run the shared typed stages with a caller-owned observer.
    ///
    /// Backend overrides may instead sequence the public consuming states
    /// directly; this helper is the reference orchestration.
    pub fn prove_values_with_stage_observer<O: PcsProofStageObserver>(
        self,
        sampled_points: TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
        channel: &mut MC::C,
        observer: &mut O,
    ) -> ExtendedCommitmentSchemeProof<MC::H> {
        self.prove_values_with_observers(
            sampled_points,
            channel,
            observer,
            &mut NoopFriCommitObserver,
        )
    }

    /// Run the shared typed stages with caller-owned stage and FRI observers.
    pub fn prove_values_with_observers<O, FO>(
        self,
        sampled_points: TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
        channel: &mut MC::C,
        observer: &mut O,
        fri_observer: &mut FO,
    ) -> ExtendedCommitmentSchemeProof<MC::H>
    where
        O: PcsProofStageObserver,
        FO: FriCommitObserver<B, MC> + ?Sized,
    {
        self.begin_proof_driver(sampled_points)
            .evaluate_oods(channel, observer)
            .compute_quotient_and_compact(channel, observer)
            .with_fri_commit_observer(
                channel,
                observer,
                fri_observer,
                |committed, channel, observer| {
                    committed
                        .prove_work_and_draw_queries(channel, observer)
                        .decommit_trees(observer)
                        .assemble(observer)
                },
            )
    }
}

impl<'a, B: BackendForChannel<MC>, MC: MerkleChannel> PcsOodsStage<'a, B, MC> {
    pub fn evaluate_oods<O: PcsProofStageObserver>(
        self,
        channel: &mut MC::C,
        observer: &mut O,
    ) -> PcsQuotientStage<'a, B, MC> {
        observer.stage_started(PcsProofStage::OodsEvaluation);
        let Self {
            scheme,
            sampled_points,
            mut timer,
        } = self;

        let span = span!(
            Level::INFO,
            "Evaluate columns out of domain",
            class = "EvaluateOutOfDomain"
        )
        .entered();

        let lifting_log_size = scheme.trees.last().unwrap().commitment.log_size();
        let weights_hash_map = if scheme.store_polynomials_coefficients {
            None
        } else {
            Some(scheme.build_weights_hash_map(&sampled_points, lifting_log_size))
        };

        let eval_at_points = |(poly, points): (
            &crate::prover::air::component_prover::Poly<B>,
            &Vec<CirclePoint<SecureField>>,
        )| {
            points
                .iter()
                .map(|&point| PointSample {
                    point,
                    value: poly.eval_at_point(
                        point.repeated_double(lifting_log_size - poly.evals.domain.log_size()),
                        weights_hash_map.as_ref(),
                    ),
                })
                .collect_vec()
        };

        let samples: TreeVec<Vec<Vec<PointSample>>> = if let Some(cache) = &weights_hash_map {
            let polys = scheme.polynomials();
            let mut groups: std::collections::HashMap<
                (u32, CirclePoint<SecureField>),
                Vec<(usize, usize, usize)>,
            > = std::collections::HashMap::new();
            for (t, (tree_polys, tree_points)) in
                polys.0.iter().zip(sampled_points.0.iter()).enumerate()
            {
                for (c, (poly, points)) in tree_polys.iter().zip(tree_points.iter()).enumerate() {
                    let log_size = poly.evals.domain.log_size();
                    for (k, &point) in points.iter().enumerate() {
                        let folded = point.repeated_double(lifting_log_size - log_size);
                        groups
                            .entry((log_size, folded))
                            .or_default()
                            .push((t, c, k));
                    }
                }
            }
            let mut out: TreeVec<Vec<Vec<PointSample>>> = TreeVec(
                sampled_points
                    .0
                    .iter()
                    .map(|tree| {
                        tree.iter()
                            .map(|pts| {
                                pts.iter()
                                    .map(|&point| PointSample {
                                        point,
                                        value: SecureField::default(),
                                    })
                                    .collect_vec()
                            })
                            .collect_vec()
                    })
                    .collect_vec(),
            );
            for ((log_size, folded), entries) in groups {
                let evals_refs: Vec<&CircleEvaluation<B, BaseField, BitReversedOrder>> = entries
                    .iter()
                    .map(|&(t, c, _)| &polys.0[t][c].evals)
                    .collect_vec();
                let values = cache.with_weights(
                    (log_size, folded),
                    || {
                        CircleEvaluation::<B, BaseField, BitReversedOrder>::barycentric_weights(
                            CanonicCoset::new(log_size),
                            folded,
                        )
                    },
                    |weights| B::barycentric_eval_columns_at_point(&evals_refs, weights),
                );
                for (&(t, c, k), value) in entries.iter().zip(values) {
                    out.0[t][c][k].value = value;
                }
            }
            out
        } else {
            #[cfg(not(feature = "parallel"))]
            {
                scheme
                    .polynomials()
                    .zip_cols(&sampled_points)
                    .map_cols(eval_at_points)
            }
            #[cfg(feature = "parallel")]
            {
                scheme
                    .polynomials()
                    .zip_cols(&sampled_points)
                    .par_map_cols(eval_at_points)
            }
        };

        span.exit();
        drop(weights_hash_map);
        let sampled_values = samples
            .as_cols_ref()
            .map_cols(|x| x.iter().map(|o| o.value).collect());
        channel.mix_felts(&sampled_values.clone().flatten_cols());
        timer.mark("oods");
        observer.stage_finished(PcsProofStage::OodsEvaluation);

        PcsQuotientStage {
            scheme,
            samples,
            sampled_values,
            lifting_log_size,
            timer,
        }
    }
}

impl<'a, B: BackendForChannel<MC>, MC: MerkleChannel> PcsQuotientStage<'a, B, MC> {
    pub fn compute_quotient_and_compact<O: PcsProofStageObserver>(
        self,
        channel: &mut MC::C,
        observer: &mut O,
    ) -> PcsFriStage<'a, B, MC> {
        observer.stage_started(PcsProofStage::QuotientAndCompaction);
        let Self {
            mut scheme,
            samples,
            sampled_values,
            lifting_log_size,
            mut timer,
        } = self;

        let quotients = if scheme.stream_lde {
            let sources: TreeVec<Vec<quotient_ops::QuotientColumnSource<'_, B>>> = TreeVec(
                scheme
                    .trees
                    .as_ref()
                    .0
                    .iter()
                    .map(|tree| {
                        tree.polynomials
                            .iter()
                            .map(|poly| match &poly.coeffs {
                                Some(coeffs) => quotient_ops::QuotientColumnSource::Coeffs(
                                    coeffs,
                                    poly.evals.domain,
                                ),
                                None => quotient_ops::QuotientColumnSource::Eval(&poly.evals),
                            })
                            .collect()
                    })
                    .collect(),
            );
            quotient_ops::compute_fri_quotients_streamed(
                sources,
                &samples,
                channel.draw_secure_felt(),
                lifting_log_size,
                scheme.twiddles,
                scheme.config.fri_config.log_blowup_factor,
            )
        } else {
            let columns = scheme.evaluations();
            print_column_size_histogram::<B, MC>(&columns);
            compute_fri_quotients(
                &columns,
                &samples,
                channel.draw_secure_felt(),
                lifting_log_size,
                scheme.twiddles,
                scheme.config.fri_config.log_blowup_factor,
            )
        };

        let compact_trees: Vec<Option<CompactTreeColumns<B>>> = if scheme.low_memory
            || scheme.stream_lde
        {
            let _span = span!(Level::INFO, "Eval compaction", class = "EvalCompaction").entered();
            scheme
                .trees
                .0
                .iter_mut()
                .map(|tree| match tree {
                    MaybeOwned::Owned(tree) if !tree.polynomials.is_empty() => {
                        Some(compact_tree_columns(
                            std::mem::take(&mut tree.polynomials),
                            scheme.twiddles,
                            &scheme.base_column_pool,
                        ))
                    }
                    MaybeOwned::Borrowed(tree)
                        if !tree.polynomials.is_empty()
                            && tree.polynomials.iter().all(|p| p.coeffs.is_some()) =>
                    {
                        Some(compact_tree_columns_cloned(&tree.polynomials))
                    }
                    _ => None,
                })
                .collect()
        } else {
            scheme.trees.iter().map(|_| None).collect()
        };

        timer.mark("quotients+compaction");
        observer.stage_finished(PcsProofStage::QuotientAndCompaction);
        PcsFriStage {
            scheme,
            sampled_values,
            compact_trees,
            quotients,
            lifting_log_size,
            timer,
        }
    }
}

impl<'a, B: BackendForChannel<MC>, MC: MerkleChannel> PcsFriStage<'a, B, MC> {
    /// Commit/fold FRI, then lend the self-borrowing committed state to the
    /// caller's continuation.  `R` cannot borrow the quotient because the
    /// continuation is higher-ranked over its scope.
    pub fn with_fri_commit<O, R, F>(
        self,
        channel: &mut MC::C,
        observer: &mut O,
        continuation: F,
    ) -> R
    where
        O: PcsProofStageObserver,
        F: for<'q> FnOnce(PcsFriCommittedStage<'q, 'a, B, MC>, &mut MC::C, &mut O) -> R,
    {
        self.with_fri_commit_observer(channel, observer, &mut NoopFriCommitObserver, continuation)
    }

    /// Commit/fold FRI with a caller-owned fold observer.
    pub fn with_fri_commit_observer<O, FO, R, F>(
        self,
        channel: &mut MC::C,
        observer: &mut O,
        fri_observer: &mut FO,
        continuation: F,
    ) -> R
    where
        O: PcsProofStageObserver,
        FO: FriCommitObserver<B, MC> + ?Sized,
        F: for<'q> FnOnce(PcsFriCommittedStage<'q, 'a, B, MC>, &mut MC::C, &mut O) -> R,
    {
        observer.stage_started(PcsProofStage::FriCommitAndFold);
        let Self {
            scheme,
            sampled_values,
            compact_trees,
            quotients,
            lifting_log_size,
            mut timer,
        } = self;
        let span_fc = span!(Level::INFO, "FRI commit", class = "FriCommit").entered();
        let fri_prover = FriProver::<B, MC>::commit_with_observer(
            channel,
            scheme.config.fri_config,
            &quotients,
            scheme.twiddles,
            fri_observer,
        );
        span_fc.exit();
        timer.mark("fri_commit");
        observer.stage_finished(PcsProofStage::FriCommitAndFold);

        continuation(
            PcsFriCommittedStage {
                scheme,
                sampled_values,
                compact_trees,
                fri_prover,
                lifting_log_size,
                timer,
            },
            channel,
            observer,
        )
    }
}

impl<'q, 'a, B: BackendForChannel<MC>, MC: MerkleChannel> PcsFriCommittedStage<'q, 'a, B, MC> {
    pub fn prove_work_and_draw_queries<O: PcsProofStageObserver>(
        self,
        channel: &mut MC::C,
        observer: &mut O,
    ) -> PcsTreeDecommitStage<'a, B, MC> {
        let Self {
            scheme,
            sampled_values,
            compact_trees,
            fri_prover,
            lifting_log_size,
            mut timer,
        } = self;

        observer.stage_started(PcsProofStage::ProofOfWork);
        let span1 = span!(Level::INFO, "Grind", class = "Queries POW").entered();
        let proof_of_work = B::grind(channel, scheme.config.pow_bits);
        span1.exit();
        channel.mix_u64(proof_of_work);
        observer.stage_finished(PcsProofStage::ProofOfWork);

        observer.stage_started(PcsProofStage::FriQueryAndDecommit);
        let span_fd = span!(Level::INFO, "FRI decommit", class = "FriDecommit").entered();
        let FriDecommitResult {
            fri_proof,
            query_positions,
            unsorted_query_locations,
        } = fri_prover.decommit(channel);
        span_fd.exit();
        timer.mark("fri_decommit");
        observer.stage_finished(PcsProofStage::FriQueryAndDecommit);

        PcsTreeDecommitStage {
            scheme,
            sampled_values,
            compact_trees,
            lifting_log_size,
            proof_of_work,
            fri_proof,
            query_positions,
            unsorted_query_locations,
            timer,
        }
    }
}

impl<'a, B: BackendForChannel<MC>, MC: MerkleChannel> PcsTreeDecommitStage<'a, B, MC> {
    pub fn decommit_trees<O: PcsProofStageObserver>(
        self,
        observer: &mut O,
    ) -> PcsAssemblyStage<MC::H> {
        observer.stage_started(PcsProofStage::TreeDecommit);
        let Self {
            mut scheme,
            sampled_values,
            mut compact_trees,
            lifting_log_size,
            proof_of_work,
            fri_proof,
            query_positions,
            unsorted_query_locations,
            mut timer,
        } = self;

        let preprocessed_query_positions = prepare_preprocessed_query_positions(
            &query_positions,
            lifting_log_size,
            scheme.trees[0].commitment.log_size(),
        );
        let query_positions_tree = TreeVec::new(
            scheme
                .trees
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    if i == 0 {
                        preprocessed_query_positions.as_slice()
                    } else {
                        query_positions.as_slice()
                    }
                })
                .collect::<Vec<_>>(),
        );
        let commitments = scheme.roots();
        let span_td = span!(Level::INFO, "Trees decommit", class = "TreesDecommit").entered();
        let (queried_values, decommitments, aux): (Vec<_>, Vec<_>, Vec<_>) = scheme
            .trees
            .as_ref()
            .zip_eq(query_positions_tree)
            .0
            .into_iter()
            .zip(compact_trees.drain(..))
            .map(|((tree, query_positions), compact)| match compact {
                Some(compact) => decommit_compact_tree(
                    tree,
                    compact,
                    query_positions,
                    scheme.twiddles,
                    &scheme.base_column_pool,
                ),
                None => tree.decommit(query_positions),
            })
            .map(|(v, x)| (v, x.decommitment, x.aux))
            .multiunzip();
        span_td.exit();
        timer.mark("trees_decommit");

        for tree in &mut scheme.trees.0 {
            if let MaybeOwned::Owned(tree) = tree {
                for poly in tree.polynomials.drain(..) {
                    let log_size = poly.evals.domain.log_size();
                    scheme
                        .base_column_pool
                        .give_back(log_size, poly.evals.values);
                }
            }
        }

        let proof = ExtendedCommitmentSchemeProof {
            proof: CommitmentSchemeProof {
                commitments,
                sampled_values,
                decommitments: TreeVec(decommitments),
                queried_values: TreeVec(queried_values),
                proof_of_work,
                fri_proof: fri_proof.proof,
                config: scheme.config,
            },
            aux: CommitmentSchemeProofAux {
                unsorted_query_locations,
                trace_decommitment: TreeVec(aux),
                fri: fri_proof.aux,
            },
        };
        observer.stage_finished(PcsProofStage::TreeDecommit);
        PcsAssemblyStage { proof }
    }
}

impl<H: MerkleHasherLifted> PcsAssemblyStage<H> {
    pub fn assemble<O: PcsProofStageObserver>(
        self,
        observer: &mut O,
    ) -> ExtendedCommitmentSchemeProof<H> {
        observer.stage_started(PcsProofStage::Assembly);
        observer.stage_finished(PcsProofStage::Assembly);
        self.proof
    }
}
