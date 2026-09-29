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
        result.push(Poly::new(BaseColumn::from_cpu(values)));
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
    let components = stwo::core::air::Components { components: cairo.components(), n_preprocessed_columns: preprocessed.ids().len() };
    let masks = components.mask_points(point, max_log, false);
    let mut native_trees = Vec::new();
    for (tree, data, sizes) in [(1, &main, &logs[0]), (2, &auxiliary, &logs[1])] {
        let mut values = Vec::new();
        for (ordinal, polynomial) in polys(data, sizes, 0, sizes.len())?.into_iter().enumerate() {
            let samples = masks[tree][ordinal].iter().map(|&p| polynomial.eval_at_point(p.repeated_double(max_log-sizes[ordinal]))).collect::<Vec<_>>();
            values.push(json!({"ordinal":ordinal,"values":samples}));
        }
        native_trees.push(json!({"tree":tree,"columns":values}));
    }
    let composition = words(&path.join("coefficients-tree-3.bin"))?;
    ensure!(
        composition.len() == 8usize * (1usize << max_log),
        "composition extent differs from claim"
    );
    let samples = polys(&composition, &[max_log; 8], 0, 8)?
        .iter()
        .map(|p| p.eval_at_point(point))
        .collect::<Vec<_>>();
    let left = QM31::from_partial_evals(samples[..4].try_into().unwrap());
    let right = QM31::from_partial_evals(samples[4..].try_into().unwrap());
    let reconstructed = left + point.repeated_double(max_log - 1).x * right;
    Ok(
        json!({"full_proof_verified":false,"accepted_benchmark":false,"air_checks":checks,"native_trees":native_trees,"composition_samples":samples,"composition_polynomial_oods":reconstructed,"composition_matches_device_sampling":reconstructed==coordinate(&prefix["observed_oods"])?,"composition_matches_rust_constraints":reconstructed==coordinate(&prefix["expected_oods"])?}),
    )
}
