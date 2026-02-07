use std::env;
use std::fs;
use std::path::PathBuf;
use std::collections::BTreeMap;

use serde::Serialize;
use stwo::core::circle::{
    CirclePoint, Coset, M31_CIRCLE_GEN, M31_CIRCLE_LOG_ORDER, SECURE_FIELD_CIRCLE_GEN,
};
use stwo::core::fft::{butterfly, ibutterfly};
use stwo::core::fields::cm31::CM31;
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;
use stwo::core::fields::{ComplexConjugate, FieldExpOps};
use stwo::core::fri::{fold_circle_into_line, fold_line, FriLayerProof, FriProof};
use stwo::core::pcs::PcsConfig;
use stwo::core::pcs::quotients::{
    accumulate_row_partial_numerators, accumulate_row_quotients,
    build_samples_with_randomness_and_periodicity, denominator_inverses, fri_answers,
    quotient_constants, ColumnSampleBatch, CommitmentSchemeProof, PointSample,
};
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::{LineDomain, LinePoly};
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_index;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs::blake3_hash::{Blake3Hash, Blake3Hasher};
use stwo::core::vcs::blake2_merkle::Blake2sMerkleHasher as VcsMerkleHasher;
use stwo::core::vcs::MerkleHasher;
use stwo::core::vcs::verifier::{MerkleDecommitment, MerkleVerifier, MerkleVerificationError};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher as LiftedMerkleHasher;
use stwo::core::vcs_lifted::MerkleHasherLifted;
use stwo::core::vcs_lifted::verifier::{
    MerkleDecommitmentLifted, MerkleVerificationError as MerkleVerificationErrorLifted,
    MerkleVerifierLifted,
};

const UPSTREAM_COMMIT: &str = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";
const DEFAULT_COUNT: usize = 256;
const PCS_VECTOR_COUNT: usize = 16;
const PCS_LIFTING_LOG_SIZE: u32 = 8;
const PCS_QUERY_COUNT: usize = 4;
const FRI_FOLD_VECTOR_COUNT: usize = 32;
const PROOF_OODS_VECTOR_COUNT: usize = 32;
const PROOF_SIZE_VECTOR_COUNT: usize = 16;
const VCS_VERIFIER_VECTOR_COUNT: usize = 24;
const VCS_PROVER_VECTOR_COUNT: usize = 16;
const VCS_LIFTED_VERIFIER_VECTOR_COUNT: usize = 24;
const VCS_LIFTED_PROVER_VECTOR_COUNT: usize = 16;
const BLAKE3_VECTOR_COUNT: usize = 64;

#[derive(Debug, Clone, Serialize)]
struct Meta {
    upstream_commit: &'static str,
    sample_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct M31Vector {
    a: u32,
    b: u32,
    add: u32,
    sub: u32,
    mul: u32,
    inv_a: u32,
    div_ab: u32,
}

#[derive(Debug, Clone, Serialize)]
struct CM31Vector {
    a: [u32; 2],
    b: [u32; 2],
    add: [u32; 2],
    sub: [u32; 2],
    mul: [u32; 2],
    inv_a: [u32; 2],
    div_ab: [u32; 2],
}

#[derive(Debug, Clone, Serialize)]
struct QM31Vector {
    a: [u32; 4],
    b: [u32; 4],
    add: [u32; 4],
    sub: [u32; 4],
    mul: [u32; 4],
    inv_a: [u32; 4],
    div_ab: [u32; 4],
}

#[derive(Debug, Clone, Serialize)]
struct CircleM31Vector {
    a_scalar: u64,
    b_scalar: u64,
    log_order_a: u32,
    a: [u32; 2],
    b: [u32; 2],
    add: [u32; 2],
    sub: [u32; 2],
    double_a: [u32; 2],
    conjugate_a: [u32; 2],
}

#[derive(Debug, Clone, Serialize)]
struct FftM31Vector {
    a: u32,
    b: u32,
    twid: u32,
    butterfly: [u32; 2],
    ibutterfly: [u32; 2],
}

#[derive(Debug, Clone, Serialize)]
struct Blake3Vector {
    data: Vec<u8>,
    hash: [u8; 32],
    left: [u8; 32],
    right: [u8; 32],
    concat_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize)]
struct PointSampleVector {
    point: [[u32; 4]; 2],
    value: [u32; 4],
}

#[derive(Debug, Clone, Serialize)]
struct SampleWithRandomnessVector {
    sample: PointSampleVector,
    random_coeff: [u32; 4],
}

#[derive(Debug, Clone, Serialize)]
struct NumeratorDataVector {
    column_index: usize,
    sample_value: [u32; 4],
    random_coeff: [u32; 4],
}

#[derive(Debug, Clone, Serialize)]
struct ColumnSampleBatchVector {
    point: [[u32; 4]; 2],
    cols_vals_randpows: Vec<NumeratorDataVector>,
}

#[derive(Debug, Clone, Serialize)]
struct LineCoeffVector {
    a: [u32; 4],
    b: [u32; 4],
    c: [u32; 4],
}

#[derive(Debug, Clone, Serialize)]
struct PcsQuotientsVector {
    lifting_log_size: u32,
    column_log_sizes: Vec<Vec<u32>>,
    samples: Vec<Vec<Vec<PointSampleVector>>>,
    random_coeff: [u32; 4],
    query_positions: Vec<usize>,
    queried_values: Vec<Vec<Vec<u32>>>,
    samples_with_randomness: Vec<Vec<Vec<SampleWithRandomnessVector>>>,
    sample_batches: Vec<ColumnSampleBatchVector>,
    line_coeffs: Vec<Vec<LineCoeffVector>>,
    denominator_inverses: Vec<Vec<[u32; 2]>>,
    partial_numerators: Vec<Vec<[u32; 4]>>,
    row_quotients: Vec<[u32; 4]>,
    fri_answers: Vec<[u32; 4]>,
}

#[derive(Debug, Clone, Serialize)]
struct FriFoldVector {
    line_log_size: u32,
    line_eval: Vec<[u32; 4]>,
    alpha: [u32; 4],
    fold_line_values: Vec<[u32; 4]>,
    circle_log_size: u32,
    circle_eval: Vec<[u32; 4]>,
    fold_circle_values: Vec<[u32; 4]>,
}

#[derive(Debug, Clone, Serialize)]
struct ProofExtractOodsVector {
    composition_log_size: u32,
    oods_point: [[u32; 4]; 2],
    composition_values: Vec<[u32; 4]>,
    expected: [u32; 4],
}

#[derive(Debug, Clone, Serialize)]
struct ProofSizeBreakdownVector {
    oods_samples: usize,
    queries_values: usize,
    fri_samples: usize,
    fri_decommitments: usize,
    trace_decommitments: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ProofSizeInnerLayerVector {
    fri_witness: Vec<[u32; 4]>,
    decommitment: Vec<[u8; 32]>,
    commitment: [u8; 32],
}

#[derive(Debug, Clone, Serialize)]
struct ProofSizeVector {
    commitments: Vec<[u8; 32]>,
    sampled_values: Vec<Vec<Vec<[u32; 4]>>>,
    decommitments: Vec<Vec<[u8; 32]>>,
    queried_values: Vec<Vec<Vec<u32>>>,
    proof_of_work: u64,
    first_layer_witness: Vec<[u32; 4]>,
    first_layer_decommitment: Vec<[u8; 32]>,
    first_layer_commitment: [u8; 32],
    inner_layers: Vec<ProofSizeInnerLayerVector>,
    last_layer_poly: Vec<[u32; 4]>,
    expected_breakdown: ProofSizeBreakdownVector,
}

#[derive(Debug, Clone, Serialize)]
struct VcsLogSizeQueriesVector {
    log_size: u32,
    queries: Vec<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct VcsVerifierVector {
    case: String,
    root: [u8; 32],
    column_log_sizes: Vec<u32>,
    queries_per_log_size: Vec<VcsLogSizeQueriesVector>,
    queried_values: Vec<u32>,
    hash_witness: Vec<[u8; 32]>,
    column_witness: Vec<u32>,
    expected: String,
}

#[derive(Debug, Clone, Serialize)]
struct VcsProverVector {
    root: [u8; 32],
    column_log_sizes: Vec<u32>,
    columns: Vec<Vec<u32>>,
    queries_per_log_size: Vec<VcsLogSizeQueriesVector>,
    queried_values: Vec<u32>,
    hash_witness: Vec<[u8; 32]>,
    column_witness: Vec<u32>,
}

#[derive(Debug, Clone, Serialize)]
struct VcsLiftedProverVector {
    root: [u8; 32],
    column_log_sizes: Vec<u32>,
    columns: Vec<Vec<u32>>,
    query_positions: Vec<usize>,
    queried_values: Vec<Vec<u32>>,
    hash_witness: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize)]
struct VcsLiftedVerifierVector {
    case: String,
    root: [u8; 32],
    column_log_sizes: Vec<u32>,
    query_positions: Vec<usize>,
    queried_values: Vec<Vec<u32>>,
    hash_witness: Vec<[u8; 32]>,
    expected: String,
}

#[derive(Clone)]
struct VcsBaseCase {
    root: Blake2sHash,
    column_log_sizes: Vec<u32>,
    columns: Vec<Vec<M31>>,
    queries_per_log_size: BTreeMap<u32, Vec<usize>>,
    queried_values: Vec<M31>,
    decommitment: MerkleDecommitment<VcsMerkleHasher>,
}

#[derive(Clone)]
struct VcsLiftedBaseCase {
    root: Blake2sHash,
    column_log_sizes: Vec<u32>,
    columns: Vec<Vec<M31>>,
    query_positions: Vec<usize>,
    queried_values: Vec<Vec<M31>>,
    decommitment: MerkleDecommitmentLifted<LiftedMerkleHasher>,
}

#[derive(Debug, Clone, Serialize)]
struct FieldVectors {
    meta: Meta,
    m31: Vec<M31Vector>,
    cm31: Vec<CM31Vector>,
    qm31: Vec<QM31Vector>,
    circle_m31: Vec<CircleM31Vector>,
    fft_m31: Vec<FftM31Vector>,
    blake3: Vec<Blake3Vector>,
    pcs_quotients: Vec<PcsQuotientsVector>,
    fri_folds: Vec<FriFoldVector>,
    proof_extract_oods: Vec<ProofExtractOodsVector>,
    proof_sizes: Vec<ProofSizeVector>,
    vcs_verifier: Vec<VcsVerifierVector>,
    vcs_prover: Vec<VcsProverVector>,
    vcs_lifted_verifier: Vec<VcsLiftedVerifierVector>,
    vcs_lifted_prover: Vec<VcsLiftedProverVector>,
}

fn main() {
    let (out_path, sample_count) = parse_args();
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let vectors = generate_vectors(&mut state, sample_count);

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("failed to create vector output directory");
    }

    let serialized = serde_json::to_string_pretty(&vectors).expect("failed to serialize vectors");
    fs::write(&out_path, serialized).expect("failed to write vectors");
}

fn parse_args() -> (PathBuf, usize) {
    let mut out = PathBuf::from("vectors/fields.json");
    let mut sample_count = DEFAULT_COUNT;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                let path = args.next().expect("--out requires a path");
                out = PathBuf::from(path);
            }
            "--count" => {
                let raw = args.next().expect("--count requires a number");
                sample_count = raw.parse::<usize>().expect("--count must be a usize");
            }
            "--help" | "-h" => {
                eprintln!("Usage: stwo-vector-gen [--out <path>] [--count <n>]");
                std::process::exit(0);
            }
            _ => {
                panic!("unknown argument: {arg}");
            }
        }
    }

    (out, sample_count)
}

fn generate_vectors(state: &mut u64, sample_count: usize) -> FieldVectors {
    let mut m31 = Vec::with_capacity(sample_count);
    let mut cm31 = Vec::with_capacity(sample_count);
    let mut qm31 = Vec::with_capacity(sample_count);
    let mut circle_m31 = Vec::with_capacity(sample_count);
    let mut fft_m31 = Vec::with_capacity(sample_count);
    let mut blake3 = Vec::with_capacity(BLAKE3_VECTOR_COUNT);

    for _ in 0..sample_count {
        let a = sample_m31(state, true);
        let b = sample_m31(state, true);
        m31.push(M31Vector {
            a: encode_m31(a),
            b: encode_m31(b),
            add: encode_m31(a + b),
            sub: encode_m31(a - b),
            mul: encode_m31(a * b),
            inv_a: encode_m31(a.inverse()),
            div_ab: encode_m31(a / b),
        });
    }

    for _ in 0..sample_count {
        let a = sample_cm31(state, true);
        let b = sample_cm31(state, true);
        cm31.push(CM31Vector {
            a: encode_cm31(a),
            b: encode_cm31(b),
            add: encode_cm31(a + b),
            sub: encode_cm31(a - b),
            mul: encode_cm31(a * b),
            inv_a: encode_cm31(a.inverse()),
            div_ab: encode_cm31(a / b),
        });
    }

    for _ in 0..sample_count {
        let a = sample_qm31(state, true);
        let b = sample_qm31(state, true);
        qm31.push(QM31Vector {
            a: encode_qm31(a),
            b: encode_qm31(b),
            add: encode_qm31(a + b),
            sub: encode_qm31(a - b),
            mul: encode_qm31(a * b),
            inv_a: encode_qm31(a.inverse()),
            div_ab: encode_qm31(a / b),
        });
    }

    for _ in 0..sample_count {
        let a_scalar = sample_scalar(state);
        let b_scalar = sample_scalar(state);
        let a = M31_CIRCLE_GEN.mul(a_scalar as u128);
        let b = M31_CIRCLE_GEN.mul(b_scalar as u128);
        let log_order_a = a.log_order();
        debug_assert!(log_order_a <= M31_CIRCLE_LOG_ORDER);
        circle_m31.push(CircleM31Vector {
            a_scalar,
            b_scalar,
            log_order_a,
            a: encode_circle_point(a),
            b: encode_circle_point(b),
            add: encode_circle_point(a + b),
            sub: encode_circle_point(a - b),
            double_a: encode_circle_point(a.double()),
            conjugate_a: encode_circle_point(a.conjugate()),
        });
    }

    for _ in 0..sample_count {
        let a = sample_m31(state, false);
        let b = sample_m31(state, false);
        let twid = sample_m31(state, true);
        let itwid = twid.inverse();

        let mut v0 = a;
        let mut v1 = b;
        butterfly(&mut v0, &mut v1, twid);
        let butterfly_out = [encode_m31(v0), encode_m31(v1)];

        ibutterfly(&mut v0, &mut v1, itwid);
        let ibutterfly_out = [encode_m31(v0), encode_m31(v1)];

        fft_m31.push(FftM31Vector {
            a: encode_m31(a),
            b: encode_m31(b),
            twid: encode_m31(twid),
            butterfly: butterfly_out,
            ibutterfly: ibutterfly_out,
        });
    }

    let pcs_quotients = generate_pcs_quotients_vectors(state, PCS_VECTOR_COUNT);
    let fri_folds = generate_fri_fold_vectors(state, FRI_FOLD_VECTOR_COUNT);
    let proof_extract_oods = generate_proof_extract_oods_vectors(state, PROOF_OODS_VECTOR_COUNT);
    let proof_sizes = generate_proof_size_vectors(state, PROOF_SIZE_VECTOR_COUNT);
    let vcs_verifier = generate_vcs_verifier_vectors(state, VCS_VERIFIER_VECTOR_COUNT);
    let vcs_prover = generate_vcs_prover_vectors(state, VCS_PROVER_VECTOR_COUNT);
    let vcs_lifted_verifier =
        generate_vcs_lifted_verifier_vectors(state, VCS_LIFTED_VERIFIER_VECTOR_COUNT);
    let vcs_lifted_prover =
        generate_vcs_lifted_prover_vectors(state, VCS_LIFTED_PROVER_VECTOR_COUNT);

    for _ in 0..BLAKE3_VECTOR_COUNT {
        let data_len = next_u64(state) as usize % 96;
        let mut data = vec![0u8; data_len];
        fill_bytes(state, &mut data);
        let hash = Blake3Hasher::hash(&data);

        let mut left_data = vec![0u8; next_u64(state) as usize % 64];
        fill_bytes(state, &mut left_data);
        let mut right_data = vec![0u8; next_u64(state) as usize % 64];
        fill_bytes(state, &mut right_data);
        let left = Blake3Hasher::hash(&left_data);
        let right = Blake3Hasher::hash(&right_data);
        let concat_hash = Blake3Hasher::concat_and_hash(&left, &right);

        blake3.push(Blake3Vector {
            data,
            hash: encode_blake3_hash(hash),
            left: encode_blake3_hash(left),
            right: encode_blake3_hash(right),
            concat_hash: encode_blake3_hash(concat_hash),
        });
    }

    FieldVectors {
        meta: Meta {
            upstream_commit: UPSTREAM_COMMIT,
            sample_count,
        },
        m31,
        cm31,
        qm31,
        circle_m31,
        fft_m31,
        blake3,
        pcs_quotients,
        fri_folds,
        proof_extract_oods,
        proof_sizes,
        vcs_verifier,
        vcs_prover,
        vcs_lifted_verifier,
        vcs_lifted_prover,
    }
}

fn generate_proof_extract_oods_vectors(state: &mut u64, count: usize) -> Vec<ProofExtractOodsVector> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let composition_log_size = 2 + ((next_u64(state) as u32) % 8);
        let oods_point = sample_secure_point_non_degenerate(state);

        let mut composition_values = Vec::with_capacity(2 * 4);
        for _ in 0..(2 * 4) {
            composition_values.push(sample_qm31(state, false));
        }

        let left = composition_values[0..4]
            .try_into()
            .expect("left composition coordinates length");
        let right = composition_values[4..8]
            .try_into()
            .expect("right composition coordinates length");
        let left_eval = QM31::from_partial_evals(left);
        let right_eval = QM31::from_partial_evals(right);
        let expected = left_eval + oods_point.repeated_double(composition_log_size - 2).x * right_eval;

        out.push(ProofExtractOodsVector {
            composition_log_size,
            oods_point: encode_secure_circle_point(oods_point),
            composition_values: composition_values.into_iter().map(encode_qm31).collect(),
            expected: encode_qm31(expected),
        });
    }
    out
}

fn generate_proof_size_vectors(state: &mut u64, count: usize) -> Vec<ProofSizeVector> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let commitments_len = 1 + (next_u64(state) as usize % 3);
        let commitments = (0..commitments_len)
            .map(|_| sample_hash(state))
            .collect::<Vec<_>>();

        let sampled_tree_count = 1 + (next_u64(state) as usize % 3);
        let mut sampled_values = Vec::with_capacity(sampled_tree_count);
        for _ in 0..sampled_tree_count {
            let cols = 1 + (next_u64(state) as usize % 3);
            let mut tree = Vec::with_capacity(cols);
            for _ in 0..cols {
                let rows = 1 + (next_u64(state) as usize % 3);
                tree.push((0..rows).map(|_| sample_qm31(state, false)).collect::<Vec<_>>());
            }
            sampled_values.push(tree);
        }

        let decommitment_count = 1 + (next_u64(state) as usize % 3);
        let mut decommitments = Vec::with_capacity(decommitment_count);
        for _ in 0..decommitment_count {
            let witness_len = next_u64(state) as usize % 4;
            decommitments.push(MerkleDecommitmentLifted::<LiftedMerkleHasher> {
                hash_witness: (0..witness_len).map(|_| sample_hash(state)).collect(),
            });
        }

        let queried_tree_count = 1 + (next_u64(state) as usize % 3);
        let mut queried_values = Vec::with_capacity(queried_tree_count);
        for _ in 0..queried_tree_count {
            let cols = 1 + (next_u64(state) as usize % 3);
            let mut tree = Vec::with_capacity(cols);
            for _ in 0..cols {
                let rows = 1 + (next_u64(state) as usize % 3);
                tree.push((0..rows).map(|_| sample_m31(state, false)).collect::<Vec<_>>());
            }
            queried_values.push(tree);
        }

        let first_layer_witness = (0..(next_u64(state) as usize % 4))
            .map(|_| sample_qm31(state, false))
            .collect::<Vec<_>>();
        let first_layer_decommitment = MerkleDecommitmentLifted::<LiftedMerkleHasher> {
            hash_witness: (0..(next_u64(state) as usize % 4))
                .map(|_| sample_hash(state))
                .collect(),
        };
        let first_layer_commitment = sample_hash(state);

        let inner_count = next_u64(state) as usize % 3;
        let mut inner_layers = Vec::with_capacity(inner_count);
        for _ in 0..inner_count {
            inner_layers.push(FriLayerProof {
                fri_witness: (0..(next_u64(state) as usize % 4))
                    .map(|_| sample_qm31(state, false))
                    .collect(),
                decommitment: MerkleDecommitmentLifted::<LiftedMerkleHasher> {
                    hash_witness: (0..(next_u64(state) as usize % 4))
                        .map(|_| sample_hash(state))
                        .collect(),
                },
                commitment: sample_hash(state),
            });
        }

        let last_layer_len = 1usize << (next_u64(state) as usize % 4);
        let last_layer_poly = (0..last_layer_len)
            .map(|_| sample_qm31(state, false))
            .collect::<Vec<_>>();

        let proof = StarkProof::<LiftedMerkleHasher>(CommitmentSchemeProof {
            config: PcsConfig::default(),
            commitments: TreeVec(commitments.clone()),
            sampled_values: TreeVec(sampled_values.clone()),
            decommitments: TreeVec(decommitments.clone()),
            queried_values: TreeVec(queried_values.clone()),
            proof_of_work: next_u64(state),
            fri_proof: FriProof {
                first_layer: FriLayerProof {
                    fri_witness: first_layer_witness.clone(),
                    decommitment: first_layer_decommitment.clone(),
                    commitment: first_layer_commitment,
                },
                inner_layers: inner_layers.clone(),
                last_layer_poly: LinePoly::new(last_layer_poly.clone()),
            },
        });

        let breakdown = proof.size_breakdown_estimate();
        out.push(ProofSizeVector {
            commitments: commitments.into_iter().map(encode_hash).collect(),
            sampled_values: sampled_values
                .into_iter()
                .map(|tree| {
                    tree.into_iter()
                        .map(|col| col.into_iter().map(encode_qm31).collect())
                        .collect()
                })
                .collect(),
            decommitments: decommitments
                .into_iter()
                .map(|decommitment| decommitment.hash_witness.into_iter().map(encode_hash).collect())
                .collect(),
            queried_values: queried_values
                .into_iter()
                .map(|tree| {
                    tree.into_iter()
                        .map(|col| col.into_iter().map(encode_m31).collect())
                        .collect()
                })
                .collect(),
            proof_of_work: proof.0.proof_of_work,
            first_layer_witness: first_layer_witness.into_iter().map(encode_qm31).collect(),
            first_layer_decommitment: first_layer_decommitment
                .hash_witness
                .into_iter()
                .map(encode_hash)
                .collect(),
            first_layer_commitment: encode_hash(first_layer_commitment),
            inner_layers: inner_layers
                .into_iter()
                .map(|layer| ProofSizeInnerLayerVector {
                    fri_witness: layer.fri_witness.into_iter().map(encode_qm31).collect(),
                    decommitment: layer
                        .decommitment
                        .hash_witness
                        .into_iter()
                        .map(encode_hash)
                        .collect(),
                    commitment: encode_hash(layer.commitment),
                })
                .collect(),
            last_layer_poly: last_layer_poly.into_iter().map(encode_qm31).collect(),
            expected_breakdown: ProofSizeBreakdownVector {
                oods_samples: breakdown.oods_samples,
                queries_values: breakdown.queries_values,
                fri_samples: breakdown.fri_samples,
                fri_decommitments: breakdown.fri_decommitments,
                trace_decommitments: breakdown.trace_decommitments,
            },
        });
    }
    out
}

fn generate_vcs_verifier_vectors(state: &mut u64, count: usize) -> Vec<VcsVerifierVector> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let mut cases = build_vcs_verifier_cases(state);
        if cases.is_empty() {
            continue;
        }
        let remaining = count - out.len();
        if cases.len() > remaining {
            cases.truncate(remaining);
        }
        out.extend(cases);
    }
    out
}

fn generate_vcs_prover_vectors(state: &mut u64, count: usize) -> Vec<VcsProverVector> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let Some(base) = build_vcs_base_case(state) else {
            continue;
        };
        out.push(VcsProverVector {
            root: encode_hash(base.root),
            column_log_sizes: base.column_log_sizes.clone(),
            columns: base
                .columns
                .into_iter()
                .map(|column| column.into_iter().map(encode_m31).collect())
                .collect(),
            queries_per_log_size: base
                .queries_per_log_size
                .iter()
                .map(|(log_size, queries)| VcsLogSizeQueriesVector {
                    log_size: *log_size,
                    queries: queries.clone(),
                })
                .collect(),
            queried_values: base.queried_values.into_iter().map(encode_m31).collect(),
            hash_witness: base
                .decommitment
                .hash_witness
                .into_iter()
                .map(encode_hash)
                .collect(),
            column_witness: base
                .decommitment
                .column_witness
                .into_iter()
                .map(encode_m31)
                .collect(),
        });
    }
    out
}

fn generate_vcs_lifted_verifier_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<VcsLiftedVerifierVector> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let mut cases = build_vcs_lifted_verifier_cases(state);
        if cases.is_empty() {
            continue;
        }
        let remaining = count - out.len();
        if cases.len() > remaining {
            cases.truncate(remaining);
        }
        out.extend(cases);
    }
    out
}

fn build_vcs_lifted_verifier_cases(state: &mut u64) -> Vec<VcsLiftedVerifierVector> {
    let Some(base) = build_vcs_lifted_base_case(state) else {
        return vec![];
    };

    let root = base.root;
    let column_log_sizes = base.column_log_sizes.clone();
    let query_positions = base.query_positions.clone();
    let queried_values = base.queried_values.clone();
    let base_decommitment = base.decommitment.clone();

    let mut out = Vec::<VcsLiftedVerifierVector>::new();
    let mut push_case = |case: &str,
                         case_root: Blake2sHash,
                         case_queried_values: Vec<Vec<M31>>,
                         case_decommitment: MerkleDecommitmentLifted<LiftedMerkleHasher>| {
        let expected = run_vcs_lifted_verifier(
            case_root,
            column_log_sizes.clone(),
            query_positions.clone(),
            case_queried_values.clone(),
            case_decommitment.clone(),
        );
        out.push(VcsLiftedVerifierVector {
            case: case.to_string(),
            root: encode_hash(case_root),
            column_log_sizes: column_log_sizes.clone(),
            query_positions: query_positions.clone(),
            queried_values: case_queried_values
                .into_iter()
                .map(|column| column.into_iter().map(encode_m31).collect())
                .collect(),
            hash_witness: case_decommitment
                .hash_witness
                .into_iter()
                .map(encode_hash)
                .collect(),
            expected,
        });
    };

    push_case(
        "valid",
        root,
        queried_values.clone(),
        base_decommitment.clone(),
    );

    let mut bad_root = root;
    bad_root.0[0] ^= 1;
    push_case(
        "root_mismatch",
        bad_root,
        queried_values.clone(),
        base_decommitment.clone(),
    );

    if !base_decommitment.hash_witness.is_empty() {
        let mut short = base_decommitment.clone();
        short.hash_witness.pop();
        push_case(
            "witness_too_short",
            root,
            queried_values.clone(),
            short,
        );
    }

    let mut long = base_decommitment.clone();
    long.hash_witness.push(sample_hash(state));
    push_case("witness_too_long", root, queried_values.clone(), long);

    if !queried_values.is_empty() && !queried_values[0].is_empty() {
        let mut bad_values = queried_values.clone();
        bad_values[0][0] = sample_m31(state, false);
        push_case(
            "queried_values_mismatch",
            root,
            bad_values,
            base_decommitment,
        );
    }

    out
}

fn generate_vcs_lifted_prover_vectors(state: &mut u64, count: usize) -> Vec<VcsLiftedProverVector> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let Some(base) = build_vcs_lifted_base_case(state) else {
            continue;
        };
        out.push(VcsLiftedProverVector {
            root: encode_hash(base.root),
            column_log_sizes: base.column_log_sizes.clone(),
            columns: base
                .columns
                .into_iter()
                .map(|column| column.into_iter().map(encode_m31).collect())
                .collect(),
            query_positions: base.query_positions.clone(),
            queried_values: base
                .queried_values
                .into_iter()
                .map(|column| column.into_iter().map(encode_m31).collect())
                .collect(),
            hash_witness: base
                .decommitment
                .hash_witness
                .into_iter()
                .map(encode_hash)
                .collect(),
        });
    }
    out
}

fn build_vcs_lifted_base_case(state: &mut u64) -> Option<VcsLiftedBaseCase> {
    let n_columns = 2 + (next_u64(state) as usize % 4);
    let mut column_log_sizes = Vec::with_capacity(n_columns);
    let mut columns = Vec::with_capacity(n_columns);
    for _ in 0..n_columns {
        let log_size = 1 + (next_u64(state) as u32 % 4);
        column_log_sizes.push(log_size);
        let col = (0..(1usize << log_size))
            .map(|_| sample_m31(state, false))
            .collect::<Vec<_>>();
        columns.push(col);
    }

    let max_log_size = *column_log_sizes.iter().max().expect("at least one column");
    let domain_size = 1usize << max_log_size;
    let mut query_positions = Vec::with_capacity(4);
    let n_queries = 1 + (next_u64(state) as usize % domain_size.min(4));
    while query_positions.len() < n_queries {
        let q = next_u64(state) as usize & (domain_size - 1);
        if !query_positions.contains(&q) {
            query_positions.push(q);
        }
    }
    query_positions.sort_unstable();

    let mut sorted_indices = (0..columns.len()).collect::<Vec<_>>();
    sorted_indices.sort_by_key(|&i| (column_log_sizes[i], i));
    let sorted_columns = sorted_indices
        .iter()
        .map(|&i| &columns[i])
        .collect::<Vec<_>>();

    let leaves = build_vcs_lifted_leaves(&sorted_columns);
    let mut layers = vec![leaves];
    while layers.last().expect("at least one layer").len() > 1 {
        let prev = layers.last().expect("previous layer");
        layers.push(
            (0..(prev.len() >> 1))
                .map(|i| LiftedMerkleHasher::hash_children((prev[2 * i], prev[2 * i + 1])))
                .collect(),
        );
    }
    layers.reverse();
    let root = layers
        .first()
        .expect("root layer")
        .first()
        .copied()
        .expect("root hash");

    let max_layer_log_size = layers.len() - 1;
    let queried_values = columns
        .iter()
        .map(|col| {
            let log_size = col.len().ilog2() as usize;
            let shift = max_layer_log_size - log_size;
            query_positions
                .iter()
                .map(|pos| col[(pos >> (shift + 1) << 1) + (pos & 1)])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let mut hash_witness = Vec::<Blake2sHash>::new();
    let mut prev_layer_queries = query_positions.clone();
    prev_layer_queries.dedup();
    for layer_log_size in (0..layers.len() - 1).rev() {
        let prev_layer_hashes = layers
            .get(layer_log_size + 1)
            .expect("previous layer hashes");
        let mut curr_layer_queries = Vec::<usize>::new();
        let mut p: usize = 0;
        while p < prev_layer_queries.len() {
            let first = prev_layer_queries[p];
            let mut chunk_len = 1;
            if p + 1 < prev_layer_queries.len() && ((first ^ 1) == prev_layer_queries[p + 1]) {
                chunk_len = 2;
            }
            if chunk_len == 1 {
                hash_witness.push(prev_layer_hashes[first ^ 1]);
            }
            curr_layer_queries.push(first >> 1);
            p += chunk_len;
        }
        prev_layer_queries = curr_layer_queries;
    }

    let decommitment = MerkleDecommitmentLifted::<LiftedMerkleHasher> { hash_witness };
    let verifier = MerkleVerifierLifted::<LiftedMerkleHasher>::new(root, column_log_sizes.clone());
    if verifier
        .verify(&query_positions, queried_values.clone(), decommitment.clone())
        .is_err()
    {
        return None;
    }

    Some(VcsLiftedBaseCase {
        root,
        column_log_sizes,
        columns,
        query_positions,
        queried_values,
        decommitment,
    })
}

fn build_vcs_lifted_leaves(columns: &[&Vec<M31>]) -> Vec<Blake2sHash> {
    let hasher = LiftedMerkleHasher::default_with_initial_state();
    if columns.is_empty() {
        return vec![hasher.finalize()];
    }
    assert!(columns[0].len() >= 2, "A column must be of length >= 2.");

    let mut prev_layer: Vec<LiftedMerkleHasher> = vec![hasher; 2];
    let mut prev_layer_log_size: u32 = 1;

    let mut group_start: usize = 0;
    while group_start < columns.len() {
        let log_size = columns[group_start].len().ilog2();
        let mut group_end = group_start + 1;
        while group_end < columns.len() && columns[group_end].len().ilog2() == log_size {
            group_end += 1;
        }

        let log_ratio = log_size - prev_layer_log_size;
        prev_layer = (0..(1usize << log_size))
            .map(|idx| prev_layer[(idx >> (log_ratio + 1) << 1) + (idx & 1)].clone())
            .collect();

        for column in &columns[group_start..group_end] {
            for (i, hasher) in prev_layer.iter_mut().enumerate() {
                hasher.update_leaf(&[column[i]]);
            }
        }
        prev_layer_log_size = log_size;
        group_start = group_end;
    }

    prev_layer.into_iter().map(|h| h.finalize()).collect()
}

fn build_vcs_base_case(state: &mut u64) -> Option<VcsBaseCase> {
    let n_columns = 2 + (next_u64(state) as usize % 4);
    let mut column_log_sizes = Vec::with_capacity(n_columns);
    let mut columns = Vec::with_capacity(n_columns);
    for _ in 0..n_columns {
        let log_size = 1 + (next_u64(state) as u32 % 4);
        column_log_sizes.push(log_size);
        let col = (0..(1usize << log_size))
            .map(|_| sample_m31(state, false))
            .collect::<Vec<_>>();
        columns.push(col);
    }

    let max_log_size = *column_log_sizes.iter().max().expect("at least one column");
    let mut columns_by_layer = BTreeMap::<u32, Vec<Vec<M31>>>::new();
    for (log_size, column) in column_log_sizes.iter().copied().zip(columns.iter().cloned()) {
        columns_by_layer.entry(log_size).or_default().push(column);
    }

    let mut queries_per_log_size = BTreeMap::<u32, Vec<usize>>::new();
    for log_size in 0..=max_log_size {
        if !columns_by_layer.contains_key(&log_size) {
            continue;
        }
        let n_queries = 1 + (next_u64(state) as usize % 3);
        let mut queries = Vec::with_capacity(n_queries);
        while queries.len() < n_queries {
            let q = next_u64(state) as usize & ((1usize << log_size) - 1);
            if !queries.contains(&q) {
                queries.push(q);
            }
        }
        queries.sort_unstable();
        queries_per_log_size.insert(log_size, queries);
    }

    let mut layer_hashes = BTreeMap::<u32, Vec<Blake2sHash>>::new();
    for layer_log_size in (0..=max_log_size).rev() {
        let n_nodes = 1usize << layer_log_size;
        let layer_columns = columns_by_layer
            .get(&layer_log_size)
            .cloned()
            .unwrap_or_default();
        let prev_layer = if layer_log_size == max_log_size {
            None
        } else {
            Some(
                layer_hashes
                    .get(&(layer_log_size + 1))
                    .expect("previous layer should be available"),
            )
        };

        let mut hashes = Vec::with_capacity(n_nodes);
        for node_index in 0..n_nodes {
            let children = prev_layer.map(|p| (p[2 * node_index], p[2 * node_index + 1]));
            let node_values = layer_columns
                .iter()
                .map(|column| column[node_index])
                .collect::<Vec<_>>();
            hashes.push(VcsMerkleHasher::hash_node(children, &node_values));
        }
        layer_hashes.insert(layer_log_size, hashes);
    }
    let root = layer_hashes
        .get(&0)
        .expect("root layer")
        .first()
        .copied()
        .expect("non-empty root layer");

    let mut queried_values = Vec::<M31>::new();
    let mut hash_witness = Vec::<Blake2sHash>::new();
    let mut column_witness = Vec::<M31>::new();

    let mut last_layer_queries = Vec::<usize>::new();
    for layer_log_size in (0..=max_log_size).rev() {
        let layer_columns = columns_by_layer
            .get(&layer_log_size)
            .cloned()
            .unwrap_or_default();
        let previous_layer_hashes = if layer_log_size == max_log_size {
            None
        } else {
            Some(
                layer_hashes
                    .get(&(layer_log_size + 1))
                    .expect("previous layer hashes"),
            )
        };

        let mut layer_total_queries = Vec::<usize>::new();
        let mut prev_layer_queries = last_layer_queries.iter().copied().peekable();
        let mut layer_column_queries = queries_per_log_size
            .get(&layer_log_size)
            .map(|v| v.iter().copied())
            .into_iter()
            .flatten()
            .peekable();

        while let Some(node_index) =
            next_decommitment_node_for_prover(&mut prev_layer_queries, &mut layer_column_queries)
        {
            if let Some(prev_hashes) = previous_layer_hashes {
                if prev_layer_queries.next_if_eq(&(2 * node_index)).is_none() {
                    hash_witness.push(prev_hashes[2 * node_index]);
                }
                if prev_layer_queries.next_if_eq(&(2 * node_index + 1)).is_none() {
                    hash_witness.push(prev_hashes[2 * node_index + 1]);
                }
            }

            let node_values = layer_columns
                .iter()
                .map(|column| column[node_index])
                .collect::<Vec<_>>();
            if layer_column_queries.next_if_eq(&node_index).is_some() {
                queried_values.extend(node_values);
            } else {
                column_witness.extend(node_values);
            }
            layer_total_queries.push(node_index);
        }

        last_layer_queries = layer_total_queries;
    }

    let base_decommitment = MerkleDecommitment::<VcsMerkleHasher> {
        hash_witness,
        column_witness,
    };
    let base_expected = run_vcs_verifier(
        root,
        column_log_sizes.clone(),
        queries_per_log_size.clone(),
        queried_values.clone(),
        base_decommitment.clone(),
    );
    if base_expected != "ok" {
        return None;
    }

    Some(VcsBaseCase {
        root,
        column_log_sizes,
        columns,
        queries_per_log_size,
        queried_values,
        decommitment: base_decommitment,
    })
}

fn build_vcs_verifier_cases(state: &mut u64) -> Vec<VcsVerifierVector> {
    let Some(base) = build_vcs_base_case(state) else {
        return vec![];
    };

    let root = base.root;
    let column_log_sizes = base.column_log_sizes.clone();
    let queries_per_log_size = base.queries_per_log_size.clone();
    let queried_values = base.queried_values.clone();
    let base_decommitment = base.decommitment.clone();

    let mut out = Vec::<VcsVerifierVector>::new();
    let mut push_case = |case: &str,
                         case_root: Blake2sHash,
                         case_queried_values: Vec<M31>,
                         case_decommitment: MerkleDecommitment<VcsMerkleHasher>| {
        let expected = run_vcs_verifier(
            case_root,
            column_log_sizes.clone(),
            queries_per_log_size.clone(),
            case_queried_values.clone(),
            case_decommitment.clone(),
        );
        out.push(VcsVerifierVector {
            case: case.to_string(),
            root: encode_hash(case_root),
            column_log_sizes: column_log_sizes.clone(),
            queries_per_log_size: queries_per_log_size
                .iter()
                .map(|(log_size, queries)| VcsLogSizeQueriesVector {
                    log_size: *log_size,
                    queries: queries.clone(),
                })
                .collect(),
            queried_values: case_queried_values.into_iter().map(encode_m31).collect(),
            hash_witness: case_decommitment
                .hash_witness
                .into_iter()
                .map(encode_hash)
                .collect(),
            column_witness: case_decommitment
                .column_witness
                .into_iter()
                .map(encode_m31)
                .collect(),
            expected,
        });
    };

    push_case("valid", root, queried_values.clone(), base_decommitment.clone());

    let mut bad_root = root;
    bad_root.0[0] ^= 1;
    push_case(
        "root_mismatch",
        bad_root,
        queried_values.clone(),
        base_decommitment.clone(),
    );

    if !base_decommitment.hash_witness.is_empty() || !base_decommitment.column_witness.is_empty() {
        let mut short = base_decommitment.clone();
        if !short.hash_witness.is_empty() {
            short.hash_witness.pop();
        } else {
            short.column_witness.pop();
        }
        push_case(
            "witness_too_short",
            root,
            queried_values.clone(),
            short,
        );
    }

    let mut long = base_decommitment.clone();
    long.hash_witness.push(sample_hash(state));
    push_case("witness_too_long", root, queried_values.clone(), long);

    if !queried_values.is_empty() {
        let mut short_values = queried_values.clone();
        short_values.pop();
        push_case(
            "queried_values_too_short",
            root,
            short_values,
            base_decommitment.clone(),
        );
    }

    let mut long_values = queried_values.clone();
    long_values.push(sample_m31(state, false));
    push_case(
        "queried_values_too_long",
        root,
        long_values,
        base_decommitment,
    );

    out
}

fn next_decommitment_node_for_prover(
    prev_queries: &mut std::iter::Peekable<impl Iterator<Item = usize>>,
    layer_queries: &mut std::iter::Peekable<impl Iterator<Item = usize>>,
) -> Option<usize> {
    let prev = prev_queries.peek().map(|q| *q / 2);
    let layer = layer_queries.peek().copied();
    match (prev, layer) {
        (None, None) => None,
        (Some(v), None) | (None, Some(v)) => Some(v),
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

fn run_vcs_verifier(
    root: Blake2sHash,
    column_log_sizes: Vec<u32>,
    queries_per_log_size: BTreeMap<u32, Vec<usize>>,
    queried_values: Vec<M31>,
    decommitment: MerkleDecommitment<VcsMerkleHasher>,
) -> String {
    let verifier = MerkleVerifier::<VcsMerkleHasher>::new(root, column_log_sizes);
    match verifier.verify(&queries_per_log_size, queried_values, decommitment) {
        Ok(()) => "ok".to_string(),
        Err(err) => merkle_error_name(err).to_string(),
    }
}

fn merkle_error_name(err: MerkleVerificationError) -> &'static str {
    match err {
        MerkleVerificationError::WitnessTooShort => "WitnessTooShort",
        MerkleVerificationError::WitnessTooLong => "WitnessTooLong",
        MerkleVerificationError::TooManyQueriedValues => "TooManyQueriedValues",
        MerkleVerificationError::TooFewQueriedValues => "TooFewQueriedValues",
        MerkleVerificationError::RootMismatch => "RootMismatch",
    }
}

fn run_vcs_lifted_verifier(
    root: Blake2sHash,
    column_log_sizes: Vec<u32>,
    query_positions: Vec<usize>,
    queried_values: Vec<Vec<M31>>,
    decommitment: MerkleDecommitmentLifted<LiftedMerkleHasher>,
) -> String {
    let verifier = MerkleVerifierLifted::<LiftedMerkleHasher>::new(root, column_log_sizes);
    match verifier.verify(&query_positions, queried_values, decommitment) {
        Ok(()) => "ok".to_string(),
        Err(err) => merkle_error_name_lifted(err).to_string(),
    }
}

fn merkle_error_name_lifted(err: MerkleVerificationErrorLifted) -> &'static str {
    match err {
        MerkleVerificationErrorLifted::WitnessTooShort => "WitnessTooShort",
        MerkleVerificationErrorLifted::WitnessTooLong => "WitnessTooLong",
        MerkleVerificationErrorLifted::RootMismatch => "RootMismatch",
    }
}

fn generate_fri_fold_vectors(state: &mut u64, count: usize) -> Vec<FriFoldVector> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let line_log_size = 2 + ((next_u64(state) as u32) % 5);
        let line_len = 1usize << line_log_size;
        let line_eval = (0..line_len)
            .map(|_| sample_qm31(state, false))
            .collect::<Vec<_>>();

        let circle_log_size = 2 + ((next_u64(state) as u32) % 5);
        let circle_len = 1usize << circle_log_size;
        let circle_eval = (0..circle_len)
            .map(|_| sample_qm31(state, false))
            .collect::<Vec<_>>();

        let alpha = sample_qm31(state, true);
        let line_domain = LineDomain::new(Coset::half_odds(line_log_size));
        let (_, fold_line_values_raw) = fold_line(&line_eval, line_domain, alpha);

        let circle_domain = CanonicCoset::new(circle_log_size).circle_domain();
        let mut fold_circle_values_raw = vec![QM31::from(0); circle_eval.len() >> 1];
        fold_circle_into_line(
            &mut fold_circle_values_raw,
            &circle_eval,
            circle_domain,
            alpha,
        );

        out.push(FriFoldVector {
            line_log_size,
            line_eval: line_eval.into_iter().map(encode_qm31).collect(),
            alpha: encode_qm31(alpha),
            fold_line_values: fold_line_values_raw.into_iter().map(encode_qm31).collect(),
            circle_log_size,
            circle_eval: circle_eval.into_iter().map(encode_qm31).collect(),
            fold_circle_values: fold_circle_values_raw.into_iter().map(encode_qm31).collect(),
        });
    }
    out
}

fn generate_pcs_quotients_vectors(state: &mut u64, count: usize) -> Vec<PcsQuotientsVector> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        if let Some(v) = try_generate_pcs_quotients_vector(state) {
            out.push(v);
        }
    }
    out
}

fn try_generate_pcs_quotients_vector(state: &mut u64) -> Option<PcsQuotientsVector> {
    let n_trees = 2usize;
    let cols_per_tree = 2usize;
    let domain_size = 1usize << PCS_LIFTING_LOG_SIZE;

    let mut query_positions = Vec::with_capacity(PCS_QUERY_COUNT);
    while query_positions.len() < PCS_QUERY_COUNT {
        let q = (next_u64(state) as usize) & (domain_size - 1);
        if !query_positions.contains(&q) {
            query_positions.push(q);
        }
    }

    let mut column_log_sizes: Vec<Vec<u32>> = Vec::with_capacity(n_trees);
    let mut samples_raw: Vec<Vec<Vec<PointSample>>> = Vec::with_capacity(n_trees);
    let mut queried_values_raw: Vec<Vec<Vec<M31>>> = Vec::with_capacity(n_trees);

    for _ in 0..n_trees {
        let mut tree_sizes = Vec::with_capacity(cols_per_tree);
        let mut tree_samples = Vec::with_capacity(cols_per_tree);
        let mut tree_queries = Vec::with_capacity(cols_per_tree);

        for _ in 0..cols_per_tree {
            let log_size = 4 + ((next_u64(state) as u32) % (PCS_LIFTING_LOG_SIZE - 3));
            tree_sizes.push(log_size);

            let n_samples = if (next_u64(state) & 1) == 0 { 1 } else { 2 };
            let mut col_samples = Vec::with_capacity(n_samples);
            for _ in 0..n_samples {
                col_samples.push(PointSample {
                    point: sample_secure_point_non_degenerate(state),
                    value: sample_qm31(state, false),
                });
            }
            tree_samples.push(col_samples);

            let mut qvals = Vec::with_capacity(query_positions.len());
            for _ in 0..query_positions.len() {
                qvals.push(sample_m31(state, false));
            }
            tree_queries.push(qvals);
        }

        column_log_sizes.push(tree_sizes);
        samples_raw.push(tree_samples);
        queried_values_raw.push(tree_queries);
    }

    let random_coeff = sample_qm31(state, true);

    let sample_y_non_degenerate = samples_raw
        .iter()
        .flatten()
        .flatten()
        .all(|sample| sample.point.y != sample.point.y.complex_conjugate());
    if !sample_y_non_degenerate {
        return None;
    }

    let size_iters = column_log_sizes
        .iter()
        .cloned()
        .map(|v| v.into_iter())
        .collect::<Vec<_>>();
    let samples_with_randomness = build_samples_with_randomness_and_periodicity(
        &TreeVec(samples_raw.clone()),
        size_iters,
        PCS_LIFTING_LOG_SIZE,
        random_coeff,
    );

    let flattened_samples_with_randomness = samples_with_randomness
        .iter()
        .flatten()
        .collect::<Vec<_>>();
    let sample_batches = ColumnSampleBatch::new_vec(&flattened_samples_with_randomness);

    let sample_points = sample_batches.iter().map(|b| b.point).collect::<Vec<_>>();
    let lifting_domain = CanonicCoset::new(PCS_LIFTING_LOG_SIZE).circle_domain();
    for &position in &query_positions {
        let domain_point = lifting_domain.at(bit_reverse_index(position, PCS_LIFTING_LOG_SIZE));
        for sample_point in &sample_points {
            let prx = sample_point.x.0;
            let pry = sample_point.y.0;
            let pix = sample_point.x.1;
            let piy = sample_point.y.1;
            let denom = (prx - domain_point.x) * piy - (pry - domain_point.y) * pix;
            if encode_cm31(denom) == [0, 0] {
                return None;
            }
        }
    }

    let q_consts = quotient_constants(&sample_batches);
    let line_coeffs_raw = q_consts.line_coeffs.clone();
    let queried_values_flat = queried_values_raw
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();

    let mut denominator_inverses_out: Vec<Vec<[u32; 2]>> = Vec::with_capacity(query_positions.len());
    let mut partial_numerators_out: Vec<Vec<[u32; 4]>> = Vec::with_capacity(query_positions.len());
    let mut row_quotients_out: Vec<[u32; 4]> = Vec::with_capacity(query_positions.len());

    for (row_idx, &position) in query_positions.iter().enumerate() {
        let queried_values_at_row = queried_values_flat
            .iter()
            .map(|column| column[row_idx])
            .collect::<Vec<_>>();
        let domain_point = lifting_domain.at(bit_reverse_index(position, PCS_LIFTING_LOG_SIZE));

        let den_inv = denominator_inverses(&sample_points, domain_point);
        denominator_inverses_out.push(den_inv.into_iter().map(encode_cm31).collect());

        let partials = sample_batches
            .iter()
            .zip(line_coeffs_raw.iter())
            .map(|(batch, coeffs)| encode_qm31(accumulate_row_partial_numerators(batch, &queried_values_at_row, coeffs)))
            .collect::<Vec<_>>();
        partial_numerators_out.push(partials);

        row_quotients_out.push(encode_qm31(accumulate_row_quotients(
            &sample_batches,
            &queried_values_at_row,
            &q_consts,
            domain_point,
        )));
    }

    let fri_answers_raw = fri_answers(
        TreeVec(column_log_sizes.clone()),
        TreeVec(samples_raw.clone()),
        random_coeff,
        &query_positions,
        TreeVec(queried_values_raw.clone()),
        PCS_LIFTING_LOG_SIZE,
    )
    .ok()?;

    let samples_encoded = samples_raw
        .iter()
        .map(|tree| {
            tree.iter()
                .map(|col| col.iter().map(encode_point_sample).collect())
                .collect()
        })
        .collect();
    let queried_encoded = queried_values_raw
        .iter()
        .map(|tree| {
            tree.iter()
                .map(|col| col.iter().map(|v| encode_m31(*v)).collect())
                .collect()
        })
        .collect();
    let samples_with_randomness_encoded = samples_with_randomness
        .iter()
        .map(|tree| {
            tree.iter()
                .map(|col| {
                    col.iter()
                        .map(|(sample, random_coeff)| SampleWithRandomnessVector {
                            sample: encode_point_sample(sample),
                            random_coeff: encode_qm31(*random_coeff),
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    let sample_batches_encoded = sample_batches
        .iter()
        .map(|batch| ColumnSampleBatchVector {
            point: encode_secure_circle_point(batch.point),
            cols_vals_randpows: batch
                .cols_vals_randpows
                .iter()
                .map(|data| NumeratorDataVector {
                    column_index: data.column_index,
                    sample_value: encode_qm31(data.sample_value),
                    random_coeff: encode_qm31(data.random_coeff),
                })
                .collect(),
        })
        .collect();
    let line_coeffs_encoded = line_coeffs_raw
        .iter()
        .map(|batch_coeffs| {
            batch_coeffs
                .iter()
                .map(|(a, b, c)| LineCoeffVector {
                    a: encode_qm31(*a),
                    b: encode_qm31(*b),
                    c: encode_qm31(*c),
                })
                .collect()
        })
        .collect();

    Some(PcsQuotientsVector {
        lifting_log_size: PCS_LIFTING_LOG_SIZE,
        column_log_sizes,
        samples: samples_encoded,
        random_coeff: encode_qm31(random_coeff),
        query_positions,
        queried_values: queried_encoded,
        samples_with_randomness: samples_with_randomness_encoded,
        sample_batches: sample_batches_encoded,
        line_coeffs: line_coeffs_encoded,
        denominator_inverses: denominator_inverses_out,
        partial_numerators: partial_numerators_out,
        row_quotients: row_quotients_out,
        fri_answers: fri_answers_raw.into_iter().map(encode_qm31).collect(),
    })
}

fn encode_point_sample(sample: &PointSample) -> PointSampleVector {
    PointSampleVector {
        point: encode_secure_circle_point(sample.point),
        value: encode_qm31(sample.value),
    }
}

fn encode_m31(x: M31) -> u32 {
    x.0
}

fn encode_hash(x: Blake2sHash) -> [u8; 32] {
    x.0
}

fn encode_blake3_hash(x: Blake3Hash) -> [u8; 32] {
    x.as_ref()
        .try_into()
        .expect("blake3 hash should be 32 bytes")
}

fn encode_cm31(x: CM31) -> [u32; 2] {
    [x.0 .0, x.1 .0]
}

fn encode_qm31(x: QM31) -> [u32; 4] {
    [x.0 .0 .0, x.0 .1 .0, x.1 .0 .0, x.1 .1 .0]
}

fn encode_circle_point(p: CirclePoint<M31>) -> [u32; 2] {
    [p.x.0, p.y.0]
}

fn encode_secure_circle_point(p: CirclePoint<QM31>) -> [[u32; 4]; 2] {
    [encode_qm31(p.x), encode_qm31(p.y)]
}

fn sample_scalar(state: &mut u64) -> u64 {
    next_u64(state) & ((1u64 << M31_CIRCLE_LOG_ORDER) - 1)
}

fn sample_scalar_u128(state: &mut u64) -> u128 {
    ((next_u64(state) as u128) << 64) | (next_u64(state) as u128)
}

fn sample_hash(state: &mut u64) -> Blake2sHash {
    let mut bytes = [0u8; 32];
    fill_bytes(state, &mut bytes);
    Blake2sHash(bytes)
}

fn fill_bytes(state: &mut u64, bytes: &mut [u8]) {
    for chunk in bytes.chunks_mut(8) {
        let block = next_u64(state).to_le_bytes();
        let n = chunk.len();
        chunk.copy_from_slice(&block[..n]);
    }
}

fn sample_m31(state: &mut u64, non_zero: bool) -> M31 {
    loop {
        let candidate = (next_u64(state) as u32) & 0x7fff_ffff;
        if candidate == P {
            continue;
        }
        if non_zero && candidate == 0 {
            continue;
        }
        return M31::from_u32_unchecked(candidate);
    }
}

fn sample_cm31(state: &mut u64, non_zero: bool) -> CM31 {
    loop {
        let out = CM31(sample_m31(state, false), sample_m31(state, false));
        if non_zero && out.0 .0 == 0 && out.1 .0 == 0 {
            continue;
        }
        return out;
    }
}

fn sample_qm31(state: &mut u64, non_zero: bool) -> QM31 {
    loop {
        let out = QM31(
            CM31(sample_m31(state, false), sample_m31(state, false)),
            CM31(sample_m31(state, false), sample_m31(state, false)),
        );
        if non_zero && encode_qm31(out) == [0, 0, 0, 0] {
            continue;
        }
        return out;
    }
}

fn sample_secure_point_non_degenerate(state: &mut u64) -> CirclePoint<QM31> {
    loop {
        let point = SECURE_FIELD_CIRCLE_GEN.mul(sample_scalar_u128(state));
        if point.y != point.y.complex_conjugate() {
            return point;
        }
    }
}

fn next_u64(state: &mut u64) -> u64 {
    // Xorshift64* (deterministic, non-cryptographic).
    let mut x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    x.wrapping_mul(0x2545_f491_4f6c_dd1d)
}
