use std::env;
use std::fs;
use std::path::PathBuf;

use serde::Serialize;
use stwo::core::circle::{
    CirclePoint, Coset, M31_CIRCLE_GEN, M31_CIRCLE_LOG_ORDER, SECURE_FIELD_CIRCLE_GEN,
};
use stwo::core::fft::{butterfly, ibutterfly};
use stwo::core::fields::cm31::CM31;
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;
use stwo::core::fields::{ComplexConjugate, FieldExpOps};
use stwo::core::fri::{fold_circle_into_line, fold_line};
use stwo::core::pcs::quotients::{
    accumulate_row_partial_numerators, accumulate_row_quotients,
    build_samples_with_randomness_and_periodicity, denominator_inverses, fri_answers,
    quotient_constants, ColumnSampleBatch, PointSample,
};
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::LineDomain;
use stwo::core::utils::bit_reverse_index;

const UPSTREAM_COMMIT: &str = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";
const DEFAULT_COUNT: usize = 256;
const PCS_VECTOR_COUNT: usize = 16;
const PCS_LIFTING_LOG_SIZE: u32 = 8;
const PCS_QUERY_COUNT: usize = 4;
const FRI_FOLD_VECTOR_COUNT: usize = 32;

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
struct FieldVectors {
    meta: Meta,
    m31: Vec<M31Vector>,
    cm31: Vec<CM31Vector>,
    qm31: Vec<QM31Vector>,
    circle_m31: Vec<CircleM31Vector>,
    fft_m31: Vec<FftM31Vector>,
    pcs_quotients: Vec<PcsQuotientsVector>,
    fri_folds: Vec<FriFoldVector>,
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
        pcs_quotients,
        fri_folds,
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
