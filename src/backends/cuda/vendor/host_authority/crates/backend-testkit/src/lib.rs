//! Conformance test kit for STWO proving backends.
//!
//! A new backend (e.g. an out-of-tree GPU backend) implements stwo's backend traits and then
//! calls these assertions from its own test suite to certify itself against the [`CpuBackend`]
//! reference, without needing any downstream AIR repository in the loop:
//!
//! ```ignore
//! #[test]
//! fn conformance() {
//!     stwo_backend_testkit::assert_backend_conformance::<MyBackend, Blake2sMerkleChannel>();
//! }
//! ```
//!
//! The kit has two layers:
//! - Operation-level differential checks against [`CpuBackend`], for failure localization.
//! - An end-to-end **proof byte-equality** check: the proof produced by the backend must be
//!   identical to the reference backend's, bit for bit. This is the gate that matters in
//!   production: the proof format is consumed by fixed verifiers (e.g. the Cairo verifier), so a
//!   conforming backend must be indistinguishable from the reference at the proof level.

use itertools::Itertools;
use num_traits::Zero;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use stwo::core::air::Component;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;
use stwo::core::fields::m31::{BaseField, M31, P};
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::LineDomain;
use stwo::core::proof_of_work::GrindOps;
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{
    Backend, BackendForChannel, Col, Column, ColumnOps, CpuBackend, FromSimdColumns,
};
use stwo::prover::fri::FriOps;
use stwo::prover::line::LineEvaluation;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::secure_column::SecureColumnByCoords;
use stwo::prover::vcs_lifted::prover::MerkleProverLifted;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkBackend, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

/// Runs the full conformance suite for a backend against the [`CpuBackend`] reference.
///
/// This is the umbrella entry point; the granular assertions below can be used directly to
/// localize failures.
pub fn assert_backend_conformance<B, MC>()
where
    B: BackendForChannel<MC> + FrameworkBackend + FromSimdColumns,
    CpuBackend: BackendForChannel<MC>,
    MC: MerkleChannel,
{
    assert_column_ops_conformance::<B>();
    assert_poly_ops_conformance::<B>();
    assert_fri_fold_conformance::<B>();
    assert_accumulation_conformance::<B>();
    assert_quotient_ops_conformance::<B>();
    assert_from_simd_columns_conformance::<B>();
    assert_merkle_conformance::<B, MC>();
    assert_grind_conformance::<B, MC>();
    assert_proof_equality::<B, MC>();
}

fn random_base_field_vec(rng: &mut SmallRng, len: usize) -> Vec<BaseField> {
    (0..len)
        .map(|_| M31::reduce(rng.gen::<u32>() as u64))
        .collect()
}

/// Column construction, element access, round trip to CPU, and bit reversal must match the
/// reference backend.
pub fn assert_column_ops_conformance<B: Backend>() {
    let mut rng = SmallRng::seed_from_u64(0);
    for log_size in [4u32, 8, 12] {
        let values = random_base_field_vec(&mut rng, 1 << log_size);

        let col = Col::<B, BaseField>::from_iter(values.iter().copied());
        assert_eq!(
            col.len(),
            values.len(),
            "column length, log_size={log_size}"
        );
        assert_eq!(
            col.to_cpu(),
            values,
            "to_cpu round trip, log_size={log_size}"
        );
        assert_eq!(col.at(3), values[3], "element access, log_size={log_size}");

        let mut col_b = col.clone();
        <B as ColumnOps<BaseField>>::bit_reverse_column(&mut col_b);
        let mut reference = values.clone();
        <CpuBackend as ColumnOps<BaseField>>::bit_reverse_column(&mut reference);
        assert_eq!(
            col_b.to_cpu(),
            reference,
            "bit_reverse, log_size={log_size}"
        );
    }
}

/// Interpolation, point evaluation, domain evaluation, and the interpolate/evaluate round
/// trip must agree with the reference backend. Comparisons are representation-independent
/// (coefficient layouts are backend-specific).
pub fn assert_poly_ops_conformance<B: Backend>() {
    let mut rng = SmallRng::seed_from_u64(1);
    for log_size in [5u32, 8, 11] {
        let domain = CanonicCoset::new(log_size).circle_domain();
        let big_domain = CanonicCoset::new(log_size + 2).circle_domain();
        let values = random_base_field_vec(&mut rng, 1 << log_size);

        let twiddles_b = B::precompute_twiddles(big_domain.half_coset);
        let twiddles_cpu = CpuBackend::precompute_twiddles(big_domain.half_coset);

        let eval_b = CircleEvaluation::<B, BaseField, BitReversedOrder>::new(
            domain,
            values.iter().copied().collect(),
        );
        let eval_cpu = CircleEvaluation::<CpuBackend, BaseField, BitReversedOrder>::new(
            domain,
            values.clone(),
        );

        let poly_b = eval_b.interpolate_with_twiddles(&twiddles_b);
        let poly_cpu = eval_cpu.interpolate_with_twiddles(&twiddles_cpu);

        // Out-of-domain evaluation.
        let point = SECURE_FIELD_CIRCLE_GEN.mul(rng.gen::<u128>());
        assert_eq!(
            poly_b.eval_at_point(point),
            poly_cpu.eval_at_point(point),
            "eval_at_point, log_size={log_size}"
        );

        // Low-degree extension values.
        let lde_b = poly_b.evaluate_with_twiddles(big_domain, &twiddles_b);
        let lde_cpu = poly_cpu.evaluate_with_twiddles(big_domain, &twiddles_cpu);
        assert_eq!(
            lde_b.values.to_cpu(),
            lde_cpu.values.to_cpu(),
            "LDE values, log_size={log_size}"
        );

        // Interpolate/evaluate round trip on the polynomial's own domain must be the exact
        // identity (relied upon by the low-memory proving mode).
        let roundtrip = poly_b.evaluate_with_twiddles(domain, &twiddles_b);
        assert_eq!(
            roundtrip.values.to_cpu(),
            values,
            "interpolate/evaluate round trip, log_size={log_size}"
        );

        // Coefficient-order semantics: splitting at the mid must produce the same two
        // half-polynomials as the reference backend (the composition polynomial is committed
        // via this split). A backend whose coefficient ORDER differs would pass every
        // self-consistent check above but fail here.
        let (left_b, right_b) = B::split_at_mid(poly_b);
        let (left_cpu, right_cpu) = CpuBackend::split_at_mid(poly_cpu);
        assert_eq!(
            left_b.eval_at_point(point),
            left_cpu.eval_at_point(point),
            "split_at_mid left half, log_size={log_size}"
        );
        assert_eq!(
            right_b.eval_at_point(point),
            right_cpu.eval_at_point(point),
            "split_at_mid right half, log_size={log_size}"
        );
        // join_at_mid must be the exact inverse.
        let rejoined_b = B::join_at_mid(left_b, right_b);
        let rejoined_cpu = CpuBackend::join_at_mid(left_cpu, right_cpu);
        assert_eq!(
            rejoined_b.eval_at_point(point),
            rejoined_cpu.eval_at_point(point),
            "join_at_mid, log_size={log_size}"
        );

        // Barycentric OODS path: the weights-based evaluation used by `prove_values`.
        let coset = CanonicCoset::new(log_size);
        let weights_b =
            CircleEvaluation::<B, BaseField, BitReversedOrder>::barycentric_weights(coset, point);
        let weights_cpu =
            CircleEvaluation::<CpuBackend, BaseField, BitReversedOrder>::barycentric_weights(
                coset, point,
            );
        assert_eq!(
            weights_b.to_cpu(),
            weights_cpu.to_cpu(),
            "barycentric weights, log_size={log_size}"
        );
        let eval_b2 = CircleEvaluation::<B, BaseField, BitReversedOrder>::new(
            domain,
            values.iter().copied().collect(),
        );
        let eval_cpu2 = CircleEvaluation::<CpuBackend, BaseField, BitReversedOrder>::new(
            domain,
            values.clone(),
        );
        assert_eq!(
            eval_b2.barycentric_eval_at_point(&weights_b),
            eval_cpu2.barycentric_eval_at_point(&weights_cpu),
            "barycentric eval, log_size={log_size}"
        );
    }
}

/// FRI line folding must agree with the reference backend.
pub fn assert_fri_fold_conformance<B: Backend>() {
    let mut rng = SmallRng::seed_from_u64(2);
    for log_size in [6u32, 10] {
        let domain = LineDomain::new(CanonicCoset::new(log_size + 1).half_coset());
        let coordinate_columns: [Vec<BaseField>; 4] =
            std::array::from_fn(|_| random_base_field_vec(&mut rng, 1 << log_size));
        let alpha = SecureField::from_u32_unchecked(
            rng.gen::<u32>() % (1 << 30),
            rng.gen::<u32>() % (1 << 30),
            rng.gen::<u32>() % (1 << 30),
            rng.gen::<u32>() % (1 << 30),
        );

        let evals_b = LineEvaluation::<B>::new(
            domain,
            SecureColumnByCoords {
                columns: std::array::from_fn(|i| coordinate_columns[i].iter().copied().collect()),
            },
        );
        let evals_cpu = LineEvaluation::<CpuBackend>::new(
            domain,
            SecureColumnByCoords {
                columns: coordinate_columns.clone(),
            },
        );

        let twiddles_b = B::precompute_twiddles(domain.coset());
        let twiddles_cpu = CpuBackend::precompute_twiddles(domain.coset());

        let folded_b = B::fold_line(&evals_b, &[alpha], &twiddles_b);
        let folded_cpu = CpuBackend::fold_line(&evals_cpu, &[alpha], &twiddles_cpu);

        let folded_b_columns = folded_b.values.columns.each_ref().map(|c| c.to_cpu());
        let folded_cpu_columns = folded_cpu.values.columns.each_ref().map(|c| c.to_cpu());
        assert_eq!(
            folded_b_columns, folded_cpu_columns,
            "fold_line, log_size={log_size}"
        );
    }
}

/// The witness-transfer seam must preserve values exactly.
pub fn assert_from_simd_columns_conformance<B: FromSimdColumns>() {
    let mut rng = SmallRng::seed_from_u64(3);
    for log_size in [4u32, 10] {
        let values = random_base_field_vec(&mut rng, 1 << log_size);
        let simd_col: Col<SimdBackend, BaseField> = values.iter().copied().collect();

        let transferred = B::from_simd_base_column(simd_col.clone());
        assert_eq!(
            transferred.to_cpu(),
            values,
            "from_simd_base_column, log_size={log_size}"
        );

        let domain = CanonicCoset::new(log_size).circle_domain();
        let evals = vec![
            CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(domain, simd_col),
        ];
        let transferred = B::from_simd_evals(evals);
        assert_eq!(transferred.len(), 1);
        assert_eq!(transferred[0].domain, domain, "from_simd_evals domain");
        assert_eq!(
            transferred[0].values.to_cpu(),
            values,
            "from_simd_evals values, log_size={log_size}"
        );
    }
}

/// Lifted Merkle commitment over mixed column sizes must produce the same root, queried
/// values, and decommitment as the reference backend; the pruned commit must be equivalent to
/// the full one.
pub fn assert_merkle_conformance<B, MC>()
where
    B: BackendForChannel<MC>,
    CpuBackend: BackendForChannel<MC>,
    MC: MerkleChannel,
{
    let mut rng = SmallRng::seed_from_u64(4);
    let max_log_size: u32 = 7;
    let lifting_log_size = max_log_size + 1;
    let columns_cpu: Vec<Vec<BaseField>> = (3..=max_log_size)
        .map(|log| random_base_field_vec(&mut rng, 1 << log))
        .collect();
    let columns_b: Vec<Col<B, BaseField>> = columns_cpu
        .iter()
        .map(|c| c.iter().copied().collect())
        .collect();

    let tree_b =
        MerkleProverLifted::<B, MC::H>::commit(columns_b.iter().collect(), lifting_log_size, 0);
    let tree_cpu = MerkleProverLifted::<CpuBackend, MC::H>::commit(
        columns_cpu.iter().collect(),
        lifting_log_size,
        0,
    );
    assert_eq!(tree_b.root(), tree_cpu.root(), "Merkle root");

    let queries: Vec<usize> = vec![0, 7, 8, 100, 255];
    let (values_b, dec_b) = tree_b.decommit(&queries, columns_b.iter().collect_vec());
    let (values_cpu, dec_cpu) = tree_cpu.decommit(&queries, columns_cpu.iter().collect_vec());
    assert_eq!(values_b, values_cpu, "queried values");
    assert_eq!(
        dec_b.decommitment.hash_witness, dec_cpu.decommitment.hash_witness,
        "hash witness"
    );
    assert_eq!(
        dec_b.aux.all_node_values, dec_cpu.aux.all_node_values,
        "Merkle auxiliary node values"
    );

    // Pruned commit must be observationally identical.
    let pruned_b =
        MerkleProverLifted::<B, MC::H>::commit_pruned(columns_b.iter().collect(), lifting_log_size);
    assert_eq!(pruned_b.root(), tree_b.root(), "pruned root");
    let (values_pruned, dec_pruned) = pruned_b.decommit(&queries, columns_b.iter().collect_vec());
    assert_eq!(values_pruned, values_b, "pruned queried values");
    assert_eq!(
        dec_pruned.decommitment.hash_witness, dec_b.decommitment.hash_witness,
        "pruned hash witness"
    );
    assert_eq!(
        dec_pruned.aux.all_node_values, dec_b.aux.all_node_values,
        "pruned auxiliary node values"
    );

    // Column counts that are exact 16-word (64-byte) block multiples: the leaf hash
    // stream must end in a full last-flagged block, never a zero-padded extra block.
    // Hash implementations that buffer block-wise get this wrong only on these counts
    // (regression: an eager word-block CUDA lane produced RootMismatch solely on trees
    // whose column count was 0 mod 16 — SN_PIE_3's FRI first layer — while passing
    // every mixed-count tree).
    for n_columns in [16usize, 32] {
        let columns_cpu: Vec<Vec<BaseField>> = (0..n_columns)
            .map(|i| random_base_field_vec(&mut rng, 1 << (3 + (i % 5) as u32)))
            .collect();
        let columns_b: Vec<Col<B, BaseField>> = columns_cpu
            .iter()
            .map(|c| c.iter().copied().collect())
            .collect();
        let tree_b =
            MerkleProverLifted::<B, MC::H>::commit(columns_b.iter().collect(), lifting_log_size, 0);
        let tree_cpu = MerkleProverLifted::<CpuBackend, MC::H>::commit(
            columns_cpu.iter().collect(),
            lifting_log_size,
            0,
        );
        assert_eq!(
            tree_b.root(),
            tree_cpu.root(),
            "Merkle root, n_columns={n_columns}"
        );
        let (values_b, dec_b) = tree_b.decommit(&queries, columns_b.iter().collect_vec());
        let (values_cpu, dec_cpu) = tree_cpu.decommit(&queries, columns_cpu.iter().collect_vec());
        assert_eq!(
            values_b, values_cpu,
            "queried values, n_columns={n_columns}"
        );
        assert_eq!(
            dec_b.decommitment.hash_witness, dec_cpu.decommitment.hash_witness,
            "hash witness, n_columns={n_columns}"
        );
        assert_eq!(
            dec_b.aux.all_node_values, dec_cpu.aux.all_node_values,
            "auxiliary node values, n_columns={n_columns}"
        );
    }

    // The sparse gather must preserve the raw `P` word for leaf rehashing while
    // returning its canonical zero value to the verifier. This catches an
    // accidental `BaseField::reduce` in the PCIe gather boundary.
    let raw_p = BaseField::from_u32_unchecked(P);
    let raw_columns_cpu = vec![
        vec![
            raw_p,
            BaseField::from_u32_unchecked(1),
            raw_p,
            BaseField::from_u32_unchecked(3),
        ],
        (0..8)
            .map(|i| BaseField::from_u32_unchecked(if i == 6 { P } else { i }))
            .collect(),
    ];
    let raw_columns_b: Vec<Col<B, BaseField>> = raw_columns_cpu
        .iter()
        .map(|column| column.iter().copied().collect())
        .collect();
    let raw_tree_b =
        MerkleProverLifted::<B, MC::H>::commit_pruned(raw_columns_b.iter().collect(), 4);
    let raw_tree_cpu =
        MerkleProverLifted::<CpuBackend, MC::H>::commit_pruned(raw_columns_cpu.iter().collect(), 4);
    assert_eq!(raw_tree_b.root(), raw_tree_cpu.root(), "raw-P Merkle root");
    let raw_queries = [0, 3, 7, 15];
    let (raw_values_b, raw_dec_b) =
        raw_tree_b.decommit(&raw_queries, raw_columns_b.iter().collect_vec());
    let (raw_values_cpu, raw_dec_cpu) =
        raw_tree_cpu.decommit(&raw_queries, raw_columns_cpu.iter().collect_vec());
    assert_eq!(raw_values_b, raw_values_cpu, "raw-P queried values");
    assert_eq!(
        raw_dec_b.decommitment.hash_witness, raw_dec_cpu.decommitment.hash_witness,
        "raw-P hash witness"
    );
    assert_eq!(
        raw_dec_b.aux.all_node_values, raw_dec_cpu.aux.all_node_values,
        "raw-P auxiliary node values"
    );
}

/// Proof-of-work grinding must return the same nonce as the reference backend. (Any valid
/// nonce verifies, but proof byte-equality requires determinism: backends must return the
/// first valid nonce.)
pub fn assert_grind_conformance<B, MC>()
where
    B: BackendForChannel<MC>,
    CpuBackend: BackendForChannel<MC>,
    MC: MerkleChannel,
{
    let mut channel = MC::C::default();
    channel.mix_u64(0xC0FFEE);
    for pow_bits in [4u32, 12] {
        let nonce_b = B::grind(&channel, pow_bits);
        let nonce_cpu = CpuBackend::grind(&channel, pow_bits);
        assert_eq!(nonce_b, nonce_cpu, "grind nonce, pow_bits={pow_bits}");
    }
}

/// Secure-column accumulation and lift-and-accumulate must agree with the reference backend.
pub fn assert_accumulation_conformance<B: Backend>() {
    use stwo::prover::secure_column::SecureColumnByCoords;
    use stwo::prover::AccumulationOps;

    let mut rng = SmallRng::seed_from_u64(5);
    for log_size in [5u32, 8, 11] {
        let a: [Vec<BaseField>; 4] =
            std::array::from_fn(|_| random_base_field_vec(&mut rng, 1 << log_size));
        let b: [Vec<BaseField>; 4] =
            std::array::from_fn(|_| random_base_field_vec(&mut rng, 1 << log_size));

        let mut col_b = SecureColumnByCoords::<B> {
            columns: std::array::from_fn(|i| a[i].iter().copied().collect()),
        };
        let other_b = SecureColumnByCoords::<B> {
            columns: std::array::from_fn(|i| b[i].iter().copied().collect()),
        };
        B::accumulate(&mut col_b, &other_b);

        let mut col_cpu = SecureColumnByCoords::<CpuBackend> { columns: a.clone() };
        let other_cpu = SecureColumnByCoords::<CpuBackend> { columns: b.clone() };
        CpuBackend::accumulate(&mut col_cpu, &other_cpu);

        assert_eq!(
            col_b.columns.each_ref().map(|c| c.to_cpu()),
            col_cpu.columns,
            "accumulate, log_size={log_size}"
        );

        // lift_and_accumulate over mixed sizes.
        let small: [Vec<BaseField>; 4] =
            std::array::from_fn(|_| random_base_field_vec(&mut rng, 1 << (log_size - 2)));
        let lifted_b = B::lift_and_accumulate(vec![
            SecureColumnByCoords::<B> {
                columns: std::array::from_fn(|i| small[i].iter().copied().collect()),
            },
            SecureColumnByCoords::<B> {
                columns: std::array::from_fn(|i| a[i].iter().copied().collect()),
            },
        ])
        .unwrap();
        let lifted_cpu = CpuBackend::lift_and_accumulate(vec![
            SecureColumnByCoords::<CpuBackend> {
                columns: small.clone(),
            },
            SecureColumnByCoords::<CpuBackend> { columns: a.clone() },
        ])
        .unwrap();
        assert_eq!(
            lifted_b.columns.each_ref().map(|c| c.to_cpu()),
            lifted_cpu.columns,
            "lift_and_accumulate, log_size={log_size}"
        );
    }
}

/// Quotient accumulation and combination must agree with the reference backend.
pub fn assert_quotient_ops_conformance<B: Backend>() {
    assert_quotient_ops_conformance_at::<B>(8);
}

/// Size-parameterized variant: kernel bugs can be size-dependent (grid/index math), so
/// backends should also be spot-checked at production sizes (e.g. log 19-20).
pub fn assert_quotient_ops_conformance_at<B: Backend>(log_size: u32) {
    use stwo::core::pcs::quotients::{
        build_samples_with_randomness_and_periodicity, ColumnSampleBatch, PointSample,
    };
    use stwo::core::pcs::TreeVec;
    use stwo::prover::pcs::quotient_ops::AccumulatedNumerators;
    use stwo::prover::QuotientOps;

    #[allow(non_snake_case)]
    let LOG_SIZE: u32 = log_size;
    const LOG_BLOWUP_FACTOR: u32 = 2;
    const N_COLS: usize = 7;

    let mut rng = SmallRng::seed_from_u64(6);
    let domain = CanonicCoset::new(LOG_SIZE).circle_domain();
    let column_values: Vec<Vec<BaseField>> = (0..N_COLS)
        .map(|_| random_base_field_vec(&mut rng, 1 << LOG_SIZE))
        .collect();

    let points = [
        SECURE_FIELD_CIRCLE_GEN.mul(rng.gen::<u128>()),
        SECURE_FIELD_CIRCLE_GEN.mul(rng.gen::<u128>()),
    ];
    let samples = (0..N_COLS)
        .map(|i| {
            points
                .iter()
                .take(1 + i % 2)
                .map(|&point| PointSample {
                    point,
                    value: SecureField::from_u32_unchecked(
                        rng.gen::<u32>() % (1 << 30),
                        rng.gen::<u32>() % (1 << 30),
                        rng.gen::<u32>() % (1 << 30),
                        rng.gen::<u32>() % (1 << 30),
                    ),
                })
                .collect_vec()
        })
        .collect_vec();
    let random_coeff = SecureField::from_u32_unchecked(98, 76, 54, 32);
    let sample_batches = ColumnSampleBatch::new_vec(
        &build_samples_with_randomness_and_periodicity(
            &TreeVec(vec![samples]),
            vec![vec![LOG_SIZE; N_COLS].into_iter()],
            LOG_SIZE,
            random_coeff,
        )
        .iter()
        .flatten()
        .collect_vec(),
    );

    let columns_b: Vec<CircleEvaluation<B, BaseField, BitReversedOrder>> = column_values
        .iter()
        .map(|values| CircleEvaluation::new(domain, values.iter().copied().collect()))
        .collect();
    let columns_cpu: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> = column_values
        .iter()
        .map(|values| CircleEvaluation::new(domain, values.clone()))
        .collect();

    let mut acc_b: Vec<AccumulatedNumerators<B>> = vec![];
    B::accumulate_numerators(
        &columns_b.iter().collect_vec(),
        &sample_batches,
        &mut acc_b,
        LOG_BLOWUP_FACTOR,
    );
    let mut acc_cpu: Vec<AccumulatedNumerators<CpuBackend>> = vec![];
    CpuBackend::accumulate_numerators(
        &columns_cpu.iter().collect_vec(),
        &sample_batches,
        &mut acc_cpu,
        LOG_BLOWUP_FACTOR,
    );

    assert_eq!(acc_b.len(), acc_cpu.len(), "accumulation count");
    for (b, cpu) in acc_b.iter().zip(acc_cpu.iter()) {
        assert_eq!(
            b.first_linear_term_acc, cpu.first_linear_term_acc,
            "first linear term"
        );
        assert_eq!(
            b.partial_numerators_acc
                .columns
                .each_ref()
                .map(|c| c.to_cpu()),
            cpu.partial_numerators_acc.columns,
            "partial numerators"
        );
    }

    // Combine: requires twiddles for the lifting domain.
    let lifting_log_size = LOG_SIZE + LOG_BLOWUP_FACTOR;
    let twiddles_b = B::precompute_twiddles(
        CanonicCoset::new(lifting_log_size)
            .circle_domain()
            .half_coset,
    );
    let twiddles_cpu = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting_log_size)
            .circle_domain()
            .half_coset,
    );
    let combined_b =
        B::compute_quotients_and_combine(acc_b, lifting_log_size, LOG_BLOWUP_FACTOR, &twiddles_b);
    let combined_cpu = CpuBackend::compute_quotients_and_combine(
        acc_cpu,
        lifting_log_size,
        LOG_BLOWUP_FACTOR,
        &twiddles_cpu,
    );
    assert_eq!(
        combined_b.values.columns.each_ref().map(|c| c.to_cpu()),
        combined_cpu.values.columns,
        "combined quotients"
    );
}

/// The reference AIR for the end-to-end check: each row holds an independent sequence
/// `c_{i+2} = c_{i+1}^2 + c_i^2`.
const N_REFERENCE_COLUMNS: usize = 16;
const REFERENCE_LOG_N_ROWS: u32 = 6;

#[derive(Clone)]
pub struct ReferenceEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for ReferenceEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let mut a = eval.next_trace_mask();
        let mut b = eval.next_trace_mask();
        for _ in 2..N_REFERENCE_COLUMNS {
            let c = eval.next_trace_mask();
            eval.add_constraint(c.clone() - (a.square() + b.square()));
            a = b;
            b = c;
        }
        eval
    }
}

/// Generates the reference trace on the SIMD backend — the canonical witness-generation
/// backend — so that the end-to-end check exercises the [`FromSimdColumns`] transfer seam
/// exactly the way downstream provers do.
pub fn generate_reference_trace(
    log_n_rows: u32,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let n_rows = 1usize << log_n_rows;
    let mut columns: Vec<Vec<BaseField>> = (0..N_REFERENCE_COLUMNS)
        .map(|_| Vec::with_capacity(n_rows))
        .collect();
    for row in 0..n_rows {
        let mut a = BaseField::from_u32_unchecked(1);
        let mut b = M31::reduce(row as u64);
        columns[0].push(a);
        columns[1].push(b);
        for column in columns.iter_mut().skip(2) {
            (a, b) = (b, a.square() + b.square());
            column.push(b);
        }
    }
    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    columns
        .into_iter()
        .map(|column| {
            CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(
                domain,
                column.into_iter().collect(),
            )
        })
        .collect()
}

pub fn prove_reference<B, MC>(
    trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
) -> String
where
    B: BackendForChannel<MC> + FrameworkBackend + FromSimdColumns,
    MC: MerkleChannel,
{
    let log_n_rows = trace[0].domain.log_size();
    let config = PcsConfig::default();
    let twiddles = B::precompute_twiddles(
        CanonicCoset::new(log_n_rows + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let channel = &mut MC::C::default();
    let mut commitment_scheme = CommitmentSchemeProver::<B, MC>::new(config, &twiddles);
    // Big-trace mode: compact committed columns and regenerate bit-exactly at decommit
    // (proofs must stay byte-identical; the conformance gate verifies this holds).
    if std::env::var_os("STWO_BENCH_LOW_MEMORY").is_some() {
        commitment_scheme.set_low_memory();
    }

    // Preprocessed trace (empty).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    // Trace: generated on SIMD, transferred to the backend at the commitment boundary.
    let trace = B::from_simd_evals(trace);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(channel);

    let component = FrameworkComponent::new(
        &mut TraceLocationAllocator::default(),
        ReferenceEval { log_n_rows },
        SecureField::zero(),
    );

    let proof =
        prove::<B, MC>(&[&component], channel, commitment_scheme).expect("reference proof failed");

    // Sanity: the proof verifies.
    let verifier_channel = &mut MC::C::default();
    let verifier_commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(config);
    let sizes = component.trace_log_degree_bounds();
    verifier_commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    verifier_commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verify(
        &[&component],
        verifier_channel,
        verifier_commitment_scheme,
        proof.clone(),
    )
    .expect("reference proof does not verify");

    format!("{proof:?}")
}

/// The end-to-end gate: a proof produced by the backend must be **byte-identical** to the
/// reference backend's proof of the same statement.
pub fn assert_proof_equality<B, MC>()
where
    B: BackendForChannel<MC> + FrameworkBackend + FromSimdColumns,
    CpuBackend: BackendForChannel<MC>,
    MC: MerkleChannel,
{
    let trace = generate_reference_trace(REFERENCE_LOG_N_ROWS);

    let proof_b = prove_reference::<B, MC>(trace.clone());
    // Prove the same statement a second time in the same process: any global cache
    // keyed by a reusable identity (raw pointers, FFI buffer addresses) poisons the
    // second prove with the first prove's data. This caught a twiddle-cache aliasing
    // bug that produced valid first proofs and corrupt second proofs.
    let proof_b_again = prove_reference::<B, MC>(trace.clone());
    assert_eq!(
        proof_b, proof_b_again,
        "backend proof is not stable across repeated proves in one process"
    );
    let proof_reference = prove_reference::<CpuBackend, MC>(trace);

    assert_eq!(
        proof_b, proof_reference,
        "backend proof differs from the reference backend's proof"
    );
}

#[cfg(test)]
mod tests {
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};

    use super::*;

    /// The SIMD backend must pass its own conformance kit (this also validates the kit).
    #[test]
    fn simd_backend_conformance() {
        assert_backend_conformance::<SimdBackend, Blake2sMerkleChannel>();
    }

    #[test]
    fn simd_backend_conformance_m31_channel() {
        assert_backend_conformance::<SimdBackend, Blake2sM31MerkleChannel>();
    }

    /// The reference backend trivially conforms to itself; this pins the kit's own
    /// plumbing for non-SIMD backends.
    #[test]
    fn cpu_backend_conformance() {
        assert_backend_conformance::<CpuBackend, Blake2sMerkleChannel>();
    }
}
