use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use num_traits::Zero;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::cm31::CM31;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::{quotient_constants, ColumnSampleBatch};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;
use stwo::prover::pcs::quotient_ops::AccumulatedNumerators;
use stwo::prover::poly::circle::{CircleEvaluation, SecureEvaluation};
use stwo::prover::poly::twiddles::{TwiddleBuffer, TwiddleTree};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::QuotientOps;
use stwo_backend_metal_sys::metal::U32Buffer;

use super::accumulation::metal_secure_column_from_values;
use super::MetalBackend;
use crate::columns::base_field_vec::BaseFieldVec;
use crate::columns::secure_field_vec::SecureFieldVec;

type QuotientDomainCache = Mutex<BTreeMap<u32, Arc<(U32Buffer, U32Buffer)>>>;

fn quotient_domain_cache() -> &'static QuotientDomainCache {
    static CACHE: OnceLock<QuotientDomainCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn pack_cm31(value: CM31) -> [u32; 2] {
    [value.0 .0, value.1 .0]
}

fn pack_secure_circle_point(point: CirclePoint<SecureField>) -> [u32; 8] {
    let [x0, x1] = pack_cm31(point.x.0);
    let [x2, x3] = pack_cm31(point.x.1);
    let [y0, y1] = pack_cm31(point.y.0);
    let [y2, y3] = pack_cm31(point.y.1);
    [x0, x1, x2, x3, y0, y1, y2, y3]
}

/// Compute quotient domain coordinates on the CPU (no GPU allocation).
/// Returns raw x,y vectors suitable for later GPU upload.
pub fn compute_quotient_domain_coords_cpu(
    domain: stwo::core::poly::circle::CircleDomain,
) -> (Vec<u32>, Vec<u32>) {
    let log_size = domain.log_size();
    let row_count = 1usize << log_size;
    let mut domain_x = Vec::with_capacity(row_count);
    let mut domain_y = Vec::with_capacity(row_count);
    for row_index in 0..row_count {
        let point = domain.at(bit_reverse_index(row_index, log_size));
        domain_x.push(point.x.0);
        domain_y.push(point.y.0);
    }
    (domain_x, domain_y)
}

/// Upload pre-computed CPU domain coordinates to GPU and cache them.
#[allow(dead_code)]
pub fn upload_quotient_domain_coords(
    lifting_log_size: u32,
    domain_x: Vec<u32>,
    domain_y: Vec<u32>,
) {
    let buffers = Arc::new((
        U32Buffer::from_slice(&domain_x).expect("Metal quotient-domain x upload should initialize"),
        U32Buffer::from_slice(&domain_y).expect("Metal quotient-domain y upload should initialize"),
    ));
    quotient_domain_cache()
        .lock()
        .expect("quotient domain cache mutex should not be poisoned")
        .insert(lifting_log_size, buffers);
}

fn cached_quotient_domain_coords(
    domain: stwo::core::poly::circle::CircleDomain,
) -> Arc<(U32Buffer, U32Buffer)> {
    // NOTE: keyed by log size only; all callers pass the canonic evaluation subdomain for
    // that size, so the key is unambiguous.
    let lifting_log_size = domain.log_size();
    if let Some(buffers) = quotient_domain_cache()
        .lock()
        .expect("quotient domain cache mutex should not be poisoned")
        .get(&lifting_log_size)
        .cloned()
    {
        return buffers;
    }

    let (domain_x, domain_y) = compute_quotient_domain_coords_cpu(domain);
    let buffers = Arc::new((
        U32Buffer::from_slice(&domain_x).expect("Metal quotient-domain x upload should initialize"),
        U32Buffer::from_slice(&domain_y).expect("Metal quotient-domain y upload should initialize"),
    ));
    quotient_domain_cache()
        .lock()
        .expect("quotient domain cache mutex should not be poisoned")
        .insert(lifting_log_size, buffers.clone());
    buffers
}

impl QuotientOps for MetalBackend {
    fn accumulate_numerators(
        columns: &[&CircleEvaluation<Self, BaseField, BitReversedOrder>],
        sample_batches: &[ColumnSampleBatch],
        accumulated_numerators_vec: &mut Vec<AccumulatedNumerators<Self>>,
        log_blowup_factor: u32,
    ) {
        if sample_batches.is_empty() {
            return;
        }
        // Numerators are accumulated over the evaluation subdomain only; in bit-reversed
        // order its rows are exactly the first `size` rows of the committed columns.
        let size = columns[0].len() >> log_blowup_factor;
        let quotient_constants = quotient_constants(sample_batches);
        let n_batches = sample_batches.len();

        // Collect ALL unique column indices across ALL batches.
        let mut global_col_indices: Vec<usize> = sample_batches
            .iter()
            .flat_map(|batch| batch.cols_vals_randpows.iter().map(|d| d.column_index))
            .collect();
        global_col_indices.sort_unstable();
        global_col_indices.dedup();

        let n_unique_cols = global_col_indices.len();
        let mut global_remap: std::collections::HashMap<usize, u32> =
            std::collections::HashMap::with_capacity(n_unique_cols);
        for (compact_idx, &orig_idx) in global_col_indices.iter().enumerate() {
            global_remap.insert(orig_idx, compact_idx as u32);
        }

        // Build concatenated kernel inputs for ALL batches.
        let mut all_indices: Vec<u32> = Vec::new();
        let mut all_b_coeffs: Vec<u32> = Vec::new();
        let mut all_c_coeffs: Vec<u32> = Vec::new();
        let mut term_offsets: Vec<u32> = Vec::with_capacity(n_batches);
        let mut term_counts: Vec<u32> = Vec::with_capacity(n_batches);
        let mut first_linear_term_accs: Vec<SecureField> = Vec::with_capacity(n_batches);

        for (batch, coeffs) in sample_batches
            .iter()
            .zip(quotient_constants.line_coeffs.into_iter())
        {
            term_offsets.push(all_indices.len() as u32);
            term_counts.push(batch.cols_vals_randpows.len() as u32);

            for data in &batch.cols_vals_randpows {
                all_indices.push(
                    *global_remap
                        .get(&data.column_index)
                        .expect("Metal quotient column index should be in global remap"),
                );
            }
            for (_, b, c) in &coeffs {
                all_b_coeffs.extend(b.to_m31_array().map(|limb| limb.0));
                all_c_coeffs.extend(c.to_m31_array().map(|limb| limb.0));
            }
            first_linear_term_accs.push(coeffs.iter().map(|(a, ..)| a).sum());
        }

        let column_indices_buf = U32Buffer::from_slice(&all_indices)
            .expect("Metal quotient batched index upload should initialize");
        let b_coeffs_buf = U32Buffer::from_slice(&all_b_coeffs)
            .expect("Metal quotient batched b upload should initialize");
        let c_coeffs_buf = U32Buffer::from_slice(&all_c_coeffs)
            .expect("Metal quotient batched c upload should initialize");
        let term_offsets_buf = U32Buffer::from_slice(&term_offsets)
            .expect("Metal quotient batched term-offset upload should initialize");
        let term_counts_buf = U32Buffer::from_slice(&term_counts)
            .expect("Metal quotient batched term-count upload should initialize");

        // Use indirect dispatch (GPU virtual addresses) to avoid copying all
        // columns into a contiguous staging buffer.  This eliminates O(n_cols *
        // row_count) bytes of CPU-side memmove that dominated large groups.
        let column_bufs: Vec<&U32Buffer> = global_col_indices
            .iter()
            .map(|&orig_idx| &columns[orig_idx].values.buffer)
            .collect();
        let per_batch_coords =
            U32Buffer::accumulate_and_unpack_partial_numerators_indirect_batched(
                &column_bufs,
                &column_indices_buf,
                &b_coeffs_buf,
                &c_coeffs_buf,
                &term_offsets_buf,
                &term_counts_buf,
                size,
            )
            .expect("Metal indirect accumulate+unpack should succeed");

        // Build AccumulatedNumerators from coordinate buffers.
        for (batch_idx, batch) in sample_batches.iter().enumerate() {
            let partial_columns = per_batch_coords[batch_idx]
                .each_ref()
                .map(|buf| BaseFieldVec::from_buffer(buf.clone()));
            accumulated_numerators_vec.push(AccumulatedNumerators {
                sample_point: batch.point,
                partial_numerators_acc: stwo::prover::secure_column::SecureColumnByCoords {
                    columns: partial_columns,
                },
                first_linear_term_acc: first_linear_term_accs[batch_idx],
            });
        }
    }

    fn compute_quotients_and_combine(
        accumulations: Vec<AccumulatedNumerators<Self>>,
        lifting_log_size: u32,
        log_blowup_factor: u32,
        twiddles: &TwiddleTree<Self>,
    ) -> SecureEvaluation<Self, BitReversedOrder> {
        let eval_domain = CanonicCoset::new(lifting_log_size).circle_domain();
        let (eval_subdomain, _) = eval_domain.split(log_blowup_factor);
        let subdomain_log_size = eval_subdomain.log_size();
        if accumulations.is_empty() {
            return SecureEvaluation::new(
                eval_domain,
                metal_secure_column_from_values(vec![
                    SecureField::zero();
                    1usize << lifting_log_size
                ]),
            );
        }
        let total_partial_len = accumulations
            .iter()
            .map(|acc| acc.partial_numerators_acc.len())
            .sum::<usize>();
        let mut partial_offsets = Vec::with_capacity(accumulations.len());
        let mut partial_log_sizes = Vec::with_capacity(accumulations.len());
        let mut sample_points = Vec::with_capacity(accumulations.len() * 8);
        let mut first_linear_terms = Vec::with_capacity(accumulations.len() * 4);

        let mut partial_coords: [U32Buffer; 4] = std::array::from_fn(|_| {
            U32Buffer::uninitialized(total_partial_len)
                .expect("Metal quotient-combine partial staging should allocate")
        });
        let mut offset = 0usize;

        for accumulation in accumulations.iter() {
            let partial_len = accumulation.partial_numerators_acc.len();
            partial_offsets.push(
                offset
                    .try_into()
                    .expect("partial numerator offset should fit in u32"),
            );
            partial_log_sizes.push(accumulation.partial_numerators_acc.len().ilog2());
            sample_points.extend_from_slice(&pack_secure_circle_point(accumulation.sample_point));
            first_linear_terms.extend(
                accumulation
                    .first_linear_term_acc
                    .to_m31_array()
                    .map(|limb| limb.0),
            );

            for (coord_buffer, column) in partial_coords
                .iter_mut()
                .zip(accumulation.partial_numerators_acc.columns.each_ref())
            {
                coord_buffer
                    .copy_range_from(&column.buffer, 0, partial_len, offset)
                    .expect("Metal quotient-combine partial staging should copy");
            }
            offset += partial_len;
        }

        let sample_points = U32Buffer::from_slice(&sample_points)
            .expect("Metal quotient-combine sample-point upload should initialize");
        let first_linear_terms = U32Buffer::from_slice(&first_linear_terms)
            .expect("Metal quotient-combine first-linear-term upload should initialize");
        let partial_log_sizes = U32Buffer::from_slice(&partial_log_sizes)
            .expect("Metal quotient-combine partial log-size upload should initialize");
        let partial_offsets = U32Buffer::from_slice(&partial_offsets)
            .expect("Metal quotient-combine partial offset upload should initialize");
        let domain_coords = cached_quotient_domain_coords(eval_subdomain);
        let result = U32Buffer::compute_quotients_and_combine(
            [
                &partial_coords[0],
                &partial_coords[1],
                &partial_coords[2],
                &partial_coords[3],
            ],
            &sample_points,
            &first_linear_terms,
            &partial_log_sizes,
            &partial_offsets,
            &domain_coords.0,
            &domain_coords.1,
            subdomain_log_size,
        )
        .expect("Metal quotient-combine kernel should succeed");

        // The kernel produced the quotient evaluation on the subdomain; interpolate it and
        // re-evaluate onto the full lifting domain (mirrors the reference backends).
        let subdomain_columns = SecureFieldVec::from_buffer(result).to_base_coords();
        let subdomain_twiddles = TwiddleTree {
            root_coset: eval_subdomain.half_coset,
            // Only itwiddles are needed for the interpolation step.
            twiddles: TwiddleBuffer::empty(),
            itwiddles: twiddles
                .itwiddles
                .extract_subdomain_twiddles(eval_domain.log_size(), subdomain_log_size),
        };
        let columns = subdomain_columns.map(|column| {
            let evaluation = CircleEvaluation::<MetalBackend, BaseField, BitReversedOrder>::new(
                eval_subdomain,
                column,
            );
            evaluation
                .interpolate_with_twiddles(&subdomain_twiddles)
                .evaluate_with_twiddles(eval_domain, twiddles)
                .values
        });
        SecureEvaluation::new(
            eval_domain,
            stwo::prover::secure_column::SecureColumnByCoords { columns },
        )
    }
}
