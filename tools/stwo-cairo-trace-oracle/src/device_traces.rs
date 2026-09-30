//! Diagnostics for actual CUDA witness polynomials. No proof is accepted here.
use anyhow::{Context, Result, ensure};
use cairo_air::{
    cairo_components::CairoComponents,
    claims::{CairoClaim, CairoInteractionClaim},
    relations::CommonLookupElements,
};
use serde_json::{Value, json};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};
use stwo::{
    core::{
        circle::CirclePoint,
        fields::{m31::M31, qm31::QM31},
        pcs::TreeVec,
        poly::circle::CanonicCoset,
    },
    prover::{
        backend::simd::{SimdBackend, column::BaseColumn},
        poly::circle::CircleCoefficients,
    },
};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTrace;
use stwo_constraint_framework::{FrameworkEval, assert_constraints_on_polys};

type Poly = CircleCoefficients<SimdBackend>;
fn words(path: &Path) -> Result<Vec<M31>> {
    let bytes = std::fs::read(path)?;
    ensure!(bytes.len() % 4 == 0, "misaligned coefficient extent");
    bytes
        .chunks_exact(4)
        .map(|b| {
            let v = u32::from_le_bytes(b.try_into().unwrap());
            ensure!(v < 0x7fffffff, "noncanonical coefficient");
            Ok(M31::from_u32_unchecked(v))
        })
        .collect()
}
fn polys(data: &[M31], logs: &[u32], start: usize, end: usize) -> Result<Vec<Poly>> {
    ensure!(
        start <= end && end <= logs.len(),
        "invalid device column span"
    );
    let mut offset = logs[..start].iter().map(|&l| 1usize << l).sum::<usize>();
    let mut result = Vec::new();
    for &log in &logs[start..end] {
        let count = 1usize << log;
        let values = data
            .get(offset..offset + count)
            .context("truncated device coefficients")?;
        // CUDA emits the canonical CPU FFT basis. Rust SIMD leaves large
        // FFTs transposed in groups of 16 lanes; its evaluator expects that
        // internal layout rather than a raw canonical coefficient vector.
        let mut column = BaseColumn::from_cpu(values);
        if log > stwo::prover::backend::simd::fft::CACHED_FFT_LOG_SIZE {
            unsafe {
                stwo::prover::backend::simd::fft::transpose_vecs(
                    column.data.as_mut_ptr().cast(),
                    (log - stwo::prover::backend::simd::m31::LOG_N_LANES) as usize,
                );
            }
        }
        result.push(Poly::new(column));
        offset += count;
    }
    Ok(result)
}
fn coordinate(value: &Value) -> Result<QM31> {
    let x: [[u32; 2]; 2] = serde_json::from_value(value.clone())?;
    ensure!(
        x.iter().flatten().all(|&v| v < 0x7fffffff),
        "noncanonical secure coordinate"
    );
    Ok(QM31::from_u32_unchecked(x[0][0], x[0][1], x[1][0], x[1][1]))
}
pub fn check(
    claim: &CairoClaim,
    interaction: &CairoInteractionClaim,
    lookups: &CommonLookupElements,
    preprocessed: &PreProcessedTrace,
    point: CirclePoint<QM31>,
    max_log: u32,
    prefix: &Value,
) -> Result<Value> {
    let Some(directory) = std::env::var_os("STWO_CAIRO_TRACE_ORACLE_DEVICE_COEFFICIENTS") else {
        return Ok(Value::Null);
    };
    let path = Path::new(&directory);
    let main = words(&path.join("coefficients-tree-1.bin"))?;
    let auxiliary = words(&path.join("coefficients-tree-2.bin"))?;
    let logs = claim.log_sizes();
    ensure!(
        main.len() == logs[0].iter().map(|&l| 1usize << l).sum::<usize>(),
        "main extent differs from claim"
    );
    ensure!(
        auxiliary.len() == logs[1].iter().map(|&l| 1usize << l).sum::<usize>(),
        "interaction extent differs from claim"
    );
    let cairo = CairoComponents::new(claim, lookups, interaction, &preprocessed.ids());
    let mut checks = Vec::new();
    macro_rules! check_component {($name:ident) => {if let Some(component)=cairo.$name.as_ref() {
        let locations=component.trace_locations();
        let prep=component.preprocessed_column_indices().iter().map(|&i|preprocessed.columns[i].gen_column_simd().interpolate()).collect::<Vec<_>>();
        let columns=TreeVec::new(vec![prep,polys(&main,&logs[0],locations[1].col_start,locations[1].col_end)?,polys(&auxiliary,&logs[1],locations[2].col_start,locations[2].col_end)?]);
        let component_eval = &**component;
        let checked=catch_unwind(AssertUnwindSafe(||assert_constraints_on_polys(&columns,CanonicCoset::new(component.log_size()),|eval|{component_eval.evaluate(eval);},component.claimed_sum())));
        let failure=checked.err().map(|e|e.downcast_ref::<String>().cloned().or_else(||e.downcast_ref::<&str>().map(|s|s.to_string())).unwrap_or_else(||"constraint assertion panicked".to_string()));
        checks.push(json!({"component":stringify!($name),"rows":1usize<<component.log_size(),"all_trace_rows_satisfy_air":failure.is_none(),"failure":failure}));
    }}}
    check_component!(blake_compress_opcode);
    check_component!(blake_round);
    check_component!(blake_g);
    check_component!(blake_round_sigma);
    let components = stwo::core::air::Components {
        components: cairo.components(),
        n_preprocessed_columns: preprocessed.ids().len(),
    };
    let masks = components.mask_points(point, max_log, false);
    let mut native_trees = Vec::new();
    let mut native_samples = vec![
        preprocessed
            .columns
            .iter()
            .zip(&masks[0])
            .map(|(column, points)| {
                if points.is_empty() {
                    return Vec::new();
                }
                let poly = column.gen_column_simd().interpolate();
                points
                    .iter()
                    .map(|&p| poly.eval_at_point(p.repeated_double(max_log - column.log_size())))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    ];
    for (tree, data, sizes) in [(1, &main, &logs[0]), (2, &auxiliary, &logs[1])] {
        let mut values = Vec::new();
        let mut tree_samples = Vec::new();
        for (ordinal, polynomial) in polys(data, sizes, 0, sizes.len())?.into_iter().enumerate() {
            let samples = masks[tree][ordinal]
                .iter()
                .map(|&p| polynomial.eval_at_point(p.repeated_double(max_log - sizes[ordinal])))
                .collect::<Vec<_>>();
            values.push(json!({"ordinal":ordinal,"values":samples}));
            tree_samples.push(samples);
        }
        native_trees.push(json!({"tree":tree,"columns":values}));
        native_samples.push(tree_samples);
    }
    let native_expected = components.eval_composition_polynomial_at_point(
        point,
        &TreeVec::new(native_samples.clone()),
        coordinate(&prefix["composition_alpha"])?,
        max_log,
    );
    let composition = words(&path.join("coefficients-tree-3.bin"))?;
    ensure!(
        composition.len() == 8usize * (1usize << max_log),
        "composition extent differs from claim"
    );
    let samples = polys(&composition, &[max_log; 8], 0, 8)?
        .iter()
        .map(|p| p.eval_at_point(point))
        .collect::<Vec<_>>();
    let quotient_diagnostic = if path.join("quotient_result_coordinates.bin").exists() {
        let lifting_log = max_log + 1;
        let domain = CanonicCoset::new(lifting_log).circle_domain();
        let count = 1usize << lifting_log;
        let query_rows = [0, 1, 2, 3, count / 4, count / 2, count - 2, count - 1];
        let data = words(&path.join("quotient_result_coordinates.bin"))?;
        ensure!(data.len() == 4 * count, "quotient extent mismatch");
        let random = words(&path.join("quotient_challenge.bin"))?;
        ensure!(random.len() == 4, "quotient challenge extent mismatch");
        let alpha = QM31::from_u32_unchecked(random[0].0, random[1].0, random[2].0, random[3].0);
        let mut degrees = Vec::new();
        for coordinate in 0..4 {
            let poly = stwo::prover::poly::circle::CircleEvaluation::<
                stwo::prover::backend::CpuBackend,
                M31,
                stwo::prover::poly::BitReversedOrder,
            >::new(
                domain,
                data[coordinate * count..(coordinate + 1) * count].to_vec(),
            )
            .interpolate();
            let nonzero = poly.coeffs[count / 2..].iter().filter(|v| v.0 != 0).count();
            degrees.push(nonzero);
        }
        let pp = preprocessed
            .columns
            .iter()
            .zip(&masks[0])
            .map(|(c, p)| {
                if p.is_empty() {
                    None
                } else {
                    Some(c.gen_column_simd().interpolate())
                }
            })
            .collect::<Vec<_>>();
        let polynomial_trees = vec![
            pp,
            polys(&main, &logs[0], 0, logs[0].len())?
                .into_iter()
                .map(Some)
                .collect(),
            polys(&auxiliary, &logs[1], 0, logs[1].len())?
                .into_iter()
                .map(Some)
                .collect(),
            polys(&composition, &[max_log; 8], 0, 8)?
                .into_iter()
                .map(Some)
                .collect(),
        ];
        let mut tree_logs = vec![
            preprocessed.log_sizes(),
            logs[0].clone(),
            logs[1].clone(),
            vec![max_log; 8],
        ];
        let mut queried = Vec::new();
        for (tree, polynomials) in polynomial_trees.iter().enumerate() {
            let mut values = Vec::new();
            for (column, poly) in polynomials.iter().enumerate() {
                let points = query_rows.iter().map(|&row| {
                    domain
                        .at(stwo::core::utils::bit_reverse_index(row, lifting_log))
                        .repeated_double(max_log.saturating_sub(tree_logs[tree][column]))
                });
                let base = points
                    .map(|p| {
                        poly.as_ref().map_or(M31::from_u32_unchecked(0), |v| {
                            v.eval_at_point(p.into_ef()).0.0
                        })
                    })
                    .collect::<Vec<_>>();
                values.push(base);
            }
            queried.push(values);
        }
        native_samples.push(samples.iter().map(|&v| vec![v]).collect());
        let mut sample_points = masks.clone();
        sample_points.push(vec![vec![point]; 8]);
        let point_samples = sample_points
            .iter()
            .zip(&native_samples)
            .map(|(points, values)| {
                points
                    .iter()
                    .zip(values)
                    .map(|(p, v)| {
                        p.iter()
                            .zip(v)
                            .map(|(&point, &value)| stwo::core::pcs::quotients::PointSample {
                                point,
                                value,
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for logs in &mut tree_logs {
            for log in logs {
                *log += 1;
            }
        }
        let expected = stwo::core::pcs::quotients::fri_answers(
            TreeVec::new(tree_logs),
            TreeVec::new(point_samples),
            alpha,
            &query_rows,
            TreeVec::new(queried),
            lifting_log,
        )
        .map_err(|e| anyhow::anyhow!("pinned quotient answers failed: {e:?}"))?;
        let rows = query_rows
            .iter()
            .zip(expected)
            .map(|(&row, expected)| {
                let actual = QM31::from_u32_unchecked(
                    data[row].0,
                    data[count + row].0,
                    data[2 * count + row].0,
                    data[3 * count + row].0,
                );
                json!({"row":row,"matches":actual==expected,"actual":actual,"expected":expected})
            })
            .collect::<Vec<_>>();
        json!({"rows":rows,"coefficient_high_half_nonzeros":degrees,"quotient_has_canonical_degree":degrees.iter().all(|&n|n==0)})
    } else {
        Value::Null
    };
    let left = QM31::from_partial_evals(samples[..4].try_into().unwrap());
    let right = QM31::from_partial_evals(samples[4..].try_into().unwrap());
    let reconstructed = left + point.repeated_double(max_log - 1).x * right;
    Ok(
        json!({"full_proof_verified":false,"accepted_benchmark":false,"air_checks":checks,"quotient":quotient_diagnostic,"cairo_claim":claim,"interaction_claim":interaction,"native_trees":native_trees,"composition_samples":samples,"native_constraint_oods":native_expected,"composition_matches_native_constraints":reconstructed==native_expected,"composition_polynomial_oods":reconstructed,"composition_matches_device_sampling":reconstructed==coordinate(&prefix["observed_oods"])?,"composition_matches_legacy_prefix_constraints":reconstructed==coordinate(&prefix["expected_oods"])?}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_device_coefficients_match_cpu_across_simd_transpose_threshold() {
        let point = CirclePoint {
            x: QM31::from_u32_unchecked(19, 3, 5, 7),
            y: QM31::from_u32_unchecked(11, 13, 17, 23),
        };
        for log in [16, 18, 20] {
            let mut state = 0x81234891u32;
            let coefficients = (0..1usize << log)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    M31::from_u32_unchecked(state % 0x7fffffff)
                })
                .collect::<Vec<_>>();
            let expected =
                CircleCoefficients::<stwo::prover::backend::CpuBackend>::new(coefficients.clone())
                    .eval_at_point(point);
            assert_eq!(
                polys(&coefficients, &[log], 0, 1).unwrap()[0].eval_at_point(point),
                expected,
                "log {log}"
            );
        }
    }
}
