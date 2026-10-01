//! The compiled AIR of `proving@5a7c5ed`: `outputs/compiled_{casm,circuit}_air`.
//!
//! Each file under `compiled_jsons/` is one `air_compile::compiled_structs::CompiledAirFn`,
//! deserialized with the upstream type so that key and set order are upstream serde's own. The
//! in-circuit evaluator of a function is generated unless
//! `air_code_gen::supported_components::is_supported` rejects it for the circuit backend, in which
//! case it is hand-written upstream.

use std::path::PathBuf;

use air_code_gen::supported_components::{AutogenCodeFile, AutogenCodeType, is_supported};
use air_compile::compiled_structs::CompiledAirFn;
use anyhow::{Context, Result, ensure};
use eval_air_fn_constraints::SampleEvaluation;
use indexmap::IndexMap;

use crate::upstream::ProvingRoot;

pub struct AirSource {
    pub label: &'static str,
    pub directory: &'static str,
}

/// The Cairo AIR, whose in-circuit evaluators live in `circuit-cairo-verifier`.
pub const CAIRO_AIR: AirSource = AirSource {
    label: "cairo",
    directory: "outputs/compiled_casm_air",
};
/// The circuit AIR, whose in-circuit evaluators live in `circuit-verifier`.
pub const CIRCUIT_AIR: AirSource = AirSource {
    label: "circuit",
    directory: "outputs/compiled_circuit_air",
};

pub struct CompiledAir {
    /// Compiled functions keyed by name, in sorted file-path order.
    pub functions: IndexMap<String, CompiledAirFn>,
    pub samples: IndexMap<String, SampleEvaluation>,
}

pub fn load(root: &mut ProvingRoot, source: &AirSource) -> Result<CompiledAir> {
    let mut functions = IndexMap::new();
    for path in root.json_files(&format!("{}/compiled_jsons", source.directory))? {
        let air_fn: CompiledAirFn = serde_json::from_slice(&root.read(&path)?)
            .with_context(|| format!("{path} is not a CompiledAirFn"))?;
        ensure!(
            functions.insert(air_fn.name.clone(), air_fn).is_none(),
            "{path}: duplicate AIR function"
        );
    }
    let samples_path = format!("{}/sample_evaluations.json", source.directory);
    let samples = serde_json::from_slice(&root.read(&samples_path)?)
        .with_context(|| format!("{samples_path} is not a sample evaluation map"))?;
    Ok(CompiledAir { functions, samples })
}

/// Whether upstream generates the in-circuit evaluator of `air_fn_name`.
pub fn is_generated(air_fn_name: &str) -> bool {
    is_supported(&AutogenCodeFile {
        air_fn_name: air_fn_name.to_owned(),
        source_path: PathBuf::new(),
        dest_dir: PathBuf::new(),
        code_type: AutogenCodeType::CIRCUIT,
    })
}
