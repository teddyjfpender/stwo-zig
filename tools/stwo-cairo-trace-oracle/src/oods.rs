//! Independent polynomial samples for a rejected CUDA proof's OODS point.
//! This is failure localization and never proof acceptance.
use anyhow::{Result, ensure};
use cairo_air::{
    cairo_components::CairoComponents,
    claims::{CairoClaim, CairoInteractionClaim},
    relations::CommonLookupElements,
};
use serde_json::{Value, json};
use stwo::{
    core::{
        air::Components,
        circle::CirclePoint,
        fields::{m31::BaseField, qm31::QM31},
    },
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTrace;

type Evaluation = CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>;

fn coordinate(value: &Value) -> Result<QM31> {
    let values: [[u32; 2]; 2] = serde_json::from_value(value.clone())?;
    ensure!(
        values.iter().flatten().all(|&v| v < 0x7fffffff),
        "noncanonical point coordinate"
    );
    Ok(QM31::from_u32_unchecked(
        values[0][0],
        values[0][1],
        values[1][0],
        values[1][1],
    ))
}

pub fn build(
    input_digest: [u8; 32],
    claim: &CairoClaim,
    interaction_claim: &CairoInteractionClaim,
    lookups: &CommonLookupElements,
    preprocessed: &PreProcessedTrace,
    main: Vec<Evaluation>,
    interaction: Vec<Evaluation>,
    report: &Value,
) -> Result<Value> {
    ensure!(
        report["full_proof_verified"] == false,
        "expected diagnostic prefix report"
    );
    let point = CirclePoint {
        x: coordinate(&report["oods_point"]["x"])?,
        y: coordinate(&report["oods_point"]["y"])?,
    };
    let cairo = CairoComponents::new(claim, lookups, interaction_claim, &preprocessed.ids());
    let components = Components {
        components: cairo.components(),
        n_preprocessed_columns: preprocessed.ids().len(),
    };
    let max_log = components
        .composition_log_degree_bound()
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("invalid compact composition degree"))?;
    let masks = components.mask_points(point, max_log, false);
    let mut trees = Vec::new();
    if std::env::var_os("STWO_CAIRO_TRACE_ORACLE_PREPROCESSED_OODS").is_some() {
        let mut columns = Vec::new();
        for (ordinal, (column, points)) in preprocessed.columns.iter().zip(&masks[0]).enumerate() {
            let log_rows = column.log_size();
            let values: Vec<QM31> = if points.is_empty() {
                Vec::new()
            } else {
                let folds = max_log.checked_sub(log_rows).ok_or_else(|| {
                    anyhow::anyhow!("used preprocessed source exceeds lifting degree")
                })?;
                let polynomial = column.gen_column_simd().interpolate();
                points
                    .iter()
                    .map(|&p| polynomial.eval_at_point(p.repeated_double(folds)))
                    .collect()
            };
            columns.push(json!({ "ordinal": ordinal, "log_rows": log_rows, "values": values }));
        }
        trees.push(json!({ "tree": 0, "columns": columns }));
    }

    for (index, evaluations) in [(1, main), (2, interaction)] {
        ensure!(
            evaluations.len() == masks[index].len(),
            "column/mask extent mismatch"
        );
        let mut columns = Vec::new();
        for (ordinal, (evaluation, points)) in
            evaluations.into_iter().zip(&masks[index]).enumerate()
        {
            let log_rows = evaluation.domain.log_size();
            let polynomial = evaluation.interpolate();
            let folds = max_log
                .checked_sub(log_rows)
                .ok_or_else(|| anyhow::anyhow!("source degree exceeds lifting degree"))?;
            let values: Vec<QM31> = points
                .iter()
                .map(|&p| polynomial.eval_at_point(p.repeated_double(folds)))
                .collect();
            let extra_double_values: Vec<QM31> = points
                .iter()
                .map(|&p| polynomial.eval_at_point(p.repeated_double(folds + 1)))
                .collect();
            columns.push(
                json!({"ordinal": ordinal, "log_rows": log_rows, "values": values,
                "diagnostic_extra_double_values": extra_double_values}),
            );
        }
        trees.push(json!({"tree": index, "columns": columns}));
    }
    let device_traces = crate::device_traces::check(
        claim,
        interaction_claim,
        lookups,
        preprocessed,
        point,
        max_log,
        report,
    )?;
    Ok(
        json!({"schema": "stwo-cairo-diagnostic-oods-samples-v1", "full_proof_verified": false,
        "accepted_benchmark": false, "input_sha256": hex::encode(input_digest),
        "authority": {"stwo_cairo_revision": "82f21252a68ec006d73e299f5bf1ce6d4db0ee78", "stwo_revision": "7b211edde786775016ef3eecb837a6240d8fe792"},
        "max_log_degree_bound": max_log,
        "device_traces": device_traces, "preprocessed_sample_count": masks[0].iter().map(Vec::len).sum::<usize>(), "trees": trees}),
    )
}
