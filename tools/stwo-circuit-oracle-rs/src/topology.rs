//! Rung R6: fold topology and the leaf's Cairo preprocessed roots.
//!
//! **Fold.** For the multiverifier entry of each checked-in registry
//! (`crates/stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json`,
//! `crates/leaf_prover/tests/data/circuit_registry_canonical_small.json`), the oracle rebuilds the
//! multiverifier exactly as `circuit_params::shared_target_fixpoint` and
//! `padded_preprocessed_circuit` do: the verified proofs' layout is
//! `layout_from_component_sizes(target)`, the multiverifier is
//! `build_multiverifier_context_from_shared_config` over it (`NoValue`), padded with
//! `pad_to_targets(target)` and preprocessed. It asserts that the target is a fixpoint (the
//! multiverifier fits it), that the preprocessed layout equals the layout the verified proofs were
//! assumed to have, and that `circuit_hash_and_preprocessed_root` reproduces the registry's
//! `preprocessed_root` and `circuit_hash` (also pinned in [`goldens::REGISTRY_ENTRIES`]). It emits
//! the layout, the eleven component log sizes, per-column digests of the committed preprocessed
//! columns ([`columns::PREPROCESSED`]) and both words.
//!
//! The 45-column layout of the multiverifier `test_utils.rs` (privacy target padding) is re-derived
//! with `layout_from_component_sizes` and asserted against its upstream constant.
//!
//! **Leaf.** The leaf circuit interns the Cairo preprocessed root as a constant. The oracle commits
//! the canonical_small Cairo preprocessed trace with `generate_preprocessed_commitment_root::
//! <Blake2sM31MerkleChannel>` (as `CircuitBuilder::cairo_preprocessed_root` and
//! `export_circuit_cairo_verifier_preprocessed_roots` do) at Cairo trace log size 20 and log
//! blowups 1, 2 and 3 (lifting log sizes 21, 22 and 23), and asserts each against
//! `circuit_cairo_verifier::verify::get_preprocessed_root`. The registries' leaf entries
//! (trace log size 20, Cairo log blowup 1) use the first. Building the leaf
//! circuit itself is M6's rung.

use std::path::Path;

use anyhow::{Context, Result, ensure};
use circuit_cairo_verifier::verify::get_preprocessed_root;
use circuit_common::finalize::{ComponentSizes, compute_padded_sizes, pad_to_targets};
use circuit_common::preprocessed::{PreprocessedCircuit, layout_from_component_sizes};
use circuit_multiverifier::verify::{
    build_multiverifier_context_from_shared_config, shared_config,
};
use circuit_prover::circuit_hash::circuit_hash_and_preprocessed_root;
use circuit_verifier::statement::{all_circuit_components, circuit_component_log_sizes};
use circuits::blake::HashValue;
use circuits::ivalue::IValue;
use circuits::utils::le_u32s_from_bytes;
use serde::Serialize;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::prover::backend::Column;
use stwo::prover::backend::simd::SimdBackend;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
use stwo_cairo_prover::witness::preprocessed_trace::generate_preprocessed_commitment_root;

use crate::checkpoint::Envelope;
use crate::columns::{self, ColumnDigester, ComponentColumns};
use crate::goldens::{self, RegistryEntry};
use crate::upstream::ProvingRoot;

/// Aggregate digest of the two registry JSON files at `proving@5a7c5ed`.
pub const PINNED_REGISTRIES_SHA256: &str =
    "61e5cee886e43d8946c518169ec5d9a2d3fb8f37a51dd497cf71ca56f0102460";

/// The registries whose multiverifier entry is rebuilt, with the golden entry pinning it.
const REGISTRIES: [(&str, &str); 2] = [
    (
        "crates/stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json",
        "recursive_tree_multiverifier",
    ),
    (
        "crates/leaf_prover/tests/data/circuit_registry_canonical_small.json",
        "leaf_prover_multiverifier",
    ),
];

#[derive(Serialize)]
pub struct LayoutEntry {
    pub id: String,
    pub log_size: u32,
}

#[derive(Serialize)]
pub struct FoldRecord {
    pub registry: &'static str,
    pub golden: &'static str,
    pub fri_config: FriConfig,
    /// `cairo_prover_params.fri_config.log_blowup_factor` of the verified (canonical_small) Cairo
    /// proofs: the blowup of the leaf's Cairo preprocessed root.
    pub cairo_log_blowup_factor: u32,
    /// `circuit_proof_configs.default.component_log_sizes`, the shared padding target.
    pub target_log_sizes: TargetLogSizes,
    /// The multiverifier's own power-of-two sizes before padding to the target.
    pub unpadded_log_sizes: TargetLogSizes,
    pub trace_log_size: u32,
    pub layout: Vec<LayoutEntry>,
    /// `circuit_component_log_sizes` in `ComponentList` order.
    pub component_log_sizes: Vec<(&'static str, u32)>,
    pub preprocessed_columns: Vec<ComponentColumns>,
    pub preprocessed_columns_accumulator_sha256: String,
    pub preprocessed_root: [u32; 8],
    pub circuit_hash: [u32; 8],
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
pub struct TargetLogSizes {
    pub eq: u32,
    pub qm31_ops: u32,
    pub m31_to_u32: u32,
    pub triple_xor: u32,
    pub blake_g_gate: u32,
}

impl TargetLogSizes {
    fn sizes(self) -> ComponentSizes {
        ComponentSizes {
            eq: 1 << self.eq,
            qm31_ops: 1 << self.qm31_ops,
            m31_to_u32: 1 << self.m31_to_u32,
            triple_xor: 1 << self.triple_xor,
            blake_g_gate: 1 << self.blake_g_gate,
        }
    }

    fn of(sizes: &ComponentSizes) -> Self {
        Self {
            eq: sizes.eq.ilog2(),
            qm31_ops: sizes.qm31_ops.ilog2(),
            m31_to_u32: sizes.m31_to_u32.ilog2(),
            triple_xor: sizes.triple_xor.ilog2(),
            blake_g_gate: sizes.blake_g_gate.ilog2(),
        }
    }

    /// The `[eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate]` order of [`RegistryEntry`].
    fn gates(self) -> [u32; 5] {
        [
            self.eq,
            self.qm31_ops,
            self.triple_xor,
            self.m31_to_u32,
            self.blake_g_gate,
        ]
    }
}

#[derive(Serialize)]
pub struct CairoRootRecord {
    pub preprocessed_trace: &'static str,
    pub log_blowup_factor: u32,
    pub trace_log_size: u32,
    pub lifting_log_size: u32,
    pub preprocessed_root: [u32; 8],
}

#[derive(Serialize)]
pub struct TopologyBody {
    pub privacy_multiverifier_layout: Vec<LayoutEntry>,
    pub folds: Vec<FoldRecord>,
    pub cairo_preprocessed_roots: Vec<CairoRootRecord>,
}

fn layout_entries(layout: impl IntoIterator<Item = (String, u32)>) -> Vec<LayoutEntry> {
    layout
        .into_iter()
        .map(|(id, log_size)| LayoutEntry { id, log_size })
        .collect()
}

fn hex_words(value: &serde_json::Value, what: &str) -> Result<[u32; 8]> {
    let words = value
        .as_array()
        .with_context(|| format!("{what} is not an array"))?
        .iter()
        .map(|word| {
            let text = word
                .as_str()
                .with_context(|| format!("{what}: not a string"))?;
            let digits = text
                .strip_prefix("0x")
                .with_context(|| format!("{what}: {text} is not 0x-prefixed"))?;
            Ok(u32::from_str_radix(digits, 16)?)
        })
        .collect::<Result<Vec<_>>>()?;
    words
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} does not have eight words"))
}

fn golden(name: &str) -> Result<&'static RegistryEntry> {
    goldens::REGISTRY_ENTRIES
        .iter()
        .find(|entry| entry.name == name)
        .with_context(|| format!("no golden registry entry {name}"))
}

fn fold_record(
    root: &mut ProvingRoot,
    registry: &'static str,
    name: &'static str,
) -> Result<FoldRecord> {
    let json: serde_json::Value = serde_json::from_slice(&root.read(registry)?)?;
    let config = &json["circuit_proof_configs"]["default"];
    let fri_config: FriConfig = serde_json::from_value(config["fri_config"].clone())
        .with_context(|| format!("{registry}: fri_config"))?;
    let target_log_sizes: TargetLogSizes = {
        let sizes = &config["component_log_sizes"];
        let log = |key: &str| -> Result<u32> {
            Ok(u32::try_from(sizes[key].as_u64().with_context(|| {
                format!("{registry}: component_log_sizes.{key}")
            })?)?)
        };
        TargetLogSizes {
            eq: log("eq")?,
            qm31_ops: log("qm31_ops")?,
            m31_to_u32: log("m31_to_u32")?,
            triple_xor: log("triple_xor")?,
            blake_g_gate: log("blake_g_gate")?,
        }
    };
    let multiverifiers = json["multiverifiers"]
        .as_array()
        .with_context(|| format!("{registry}: multiverifiers"))?;
    ensure!(
        multiverifiers.len() == 1 && multiverifiers[0]["config"] == "default",
        "{registry}: expected one default multiverifier"
    );
    let expected_root = hex_words(&multiverifiers[0]["preprocessed_root"], "preprocessed_root")?;
    let expected_hash = hex_words(&multiverifiers[0]["circuit_hash"], "circuit_hash")?;
    let cairo = &json["cairo_prover_params"];
    ensure!(
        cairo["preprocessed_trace"] == "canonical_small",
        "{registry}: the verified Cairo proofs are not canonical_small"
    );
    let cairo_log_blowup_factor = u32::try_from(
        cairo["fri_config"]["log_blowup_factor"]
            .as_u64()
            .with_context(|| format!("{registry}: cairo log_blowup_factor"))?,
    )?;
    let entry = golden(name)?;
    ensure!(
        entry.registry == registry
            && entry.gates == target_log_sizes.gates()
            && entry.preprocessed_root == expected_root
            && entry.circuit_hash == expected_hash,
        "{registry}: registry JSON differs from golden {name}"
    );

    // `shared_target_fixpoint` at a converged target: build the multiverifier over the layout the
    // target implies and check it fits.
    let target = target_log_sizes.sizes();
    let layout = layout_from_component_sizes(&target);
    let trace_log_size = *layout.values().max().context("empty layout")?;
    let pcs_config = PcsConfig::from_fri_and_trace_size(fri_config, trace_log_size);
    let mut context =
        build_multiverifier_context_from_shared_config(&shared_config(layout.clone(), pcs_config));
    let unpadded = compute_padded_sizes(&context);
    ensure!(
        target.elementwise_max(&unpadded) == target,
        "{registry}: the target is not a fixpoint of the multiverifier"
    );
    pad_to_targets(&mut context, &target);
    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut context);
    drop(context);
    ensure!(
        preprocessed.preprocessed_trace.log_sizes() == layout,
        "{registry}: preprocessed layout differs from layout_from_component_sizes"
    );
    let component_log_sizes =
        circuit_component_log_sizes(&all_circuit_components::<QM31>(), &layout);

    let mut digester = ColumnDigester::new(columns::PREPROCESSED);
    let ids = preprocessed.preprocessed_trace.ids();
    let trace = preprocessed.preprocessed_trace.get_trace::<SimdBackend>();
    digester.component(
        "preprocessed",
        ids.iter()
            .zip(&trace)
            .map(|(id, eval)| (Some(id.id.clone()), eval.values.to_cpu())),
    )?;
    drop(trace);
    let (preprocessed_columns, accumulator) = digester.finish();

    let (circuit_hash, preprocessed_root) =
        circuit_hash_and_preprocessed_root(&preprocessed, fri_config.log_blowup_factor);
    let preprocessed_root: [u32; 8] = le_u32s_from_bytes(preprocessed_root.0);
    let circuit_hash: [u32; 8] = le_u32s_from_bytes(circuit_hash.0);
    ensure!(
        preprocessed_root == expected_root,
        "{registry}: multiverifier preprocessed root {preprocessed_root:x?} differs from the registry"
    );
    ensure!(
        circuit_hash == expected_hash,
        "{registry}: multiverifier circuit hash {circuit_hash:x?} differs from the registry"
    );

    Ok(FoldRecord {
        registry,
        golden: name,
        fri_config,
        cairo_log_blowup_factor,
        target_log_sizes,
        unpadded_log_sizes: TargetLogSizes::of(&unpadded),
        trace_log_size,
        layout: layout_entries(layout.iter().map(|(id, log)| (id.id.clone(), *log))),
        component_log_sizes: component_log_sizes.into_named_iter().collect(),
        preprocessed_columns,
        preprocessed_columns_accumulator_sha256: accumulator,
        preprocessed_root,
        circuit_hash,
    })
}

/// `circuit_component_log_sizes` of a preprocessed circuit, in `ComponentList` order.
pub fn component_log_sizes_of(preprocessed: &PreprocessedCircuit) -> Vec<(&'static str, u32)> {
    circuit_component_log_sizes(
        &all_circuit_components::<QM31>(),
        &preprocessed.preprocessed_trace.log_sizes(),
    )
    .into_named_iter()
    .collect()
}

fn privacy_layout() -> Result<Vec<LayoutEntry>> {
    let [eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate] = goldens::PRIVACY_TARGET_LOG_SIZES;
    let layout = layout_from_component_sizes(
        &TargetLogSizes {
            eq,
            qm31_ops,
            m31_to_u32,
            triple_xor,
            blake_g_gate,
        }
        .sizes(),
    );
    let entries: Vec<(String, u32)> = layout
        .iter()
        .map(|(id, log)| (id.id.clone(), *log))
        .collect();
    let expected: Vec<(String, u32)> = goldens::MULTIVERIFIER_PRIVACY_LAYOUT
        .iter()
        .map(|(id, log)| ((*id).to_owned(), *log))
        .collect();
    ensure!(
        entries == expected,
        "layout_from_component_sizes differs from {}",
        goldens::MULTIVERIFIER_TEST_UTILS
    );
    Ok(layout_entries(entries))
}

fn cairo_root(log_blowup_factor: u32) -> Result<CairoRootRecord> {
    let lifting_log_size = goldens::CAIRO_PREPROCESSED_ROOT_TRACE_LOG_SIZE + log_blowup_factor;
    let root = generate_preprocessed_commitment_root::<Blake2sM31MerkleChannel>(
        log_blowup_factor,
        PreProcessedTraceVariant::CanonicalSmall,
        lifting_log_size,
    );
    let words: [u32; 8] = le_u32s_from_bytes(root.0);
    let expected: HashValue<QM31> = get_preprocessed_root(lifting_log_size);
    let expected = expected.0.map(|word| word.get().unpack_u32());
    ensure!(
        words == expected,
        "canonical_small Cairo root at lifting log size {lifting_log_size} differs from {}",
        goldens::CAIRO_PREPROCESSED_ROOT_SOURCE
    );
    Ok(CairoRootRecord {
        preprocessed_trace: "canonical_small",
        log_blowup_factor,
        trace_log_size: goldens::CAIRO_PREPROCESSED_ROOT_TRACE_LOG_SIZE,
        lifting_log_size,
        preprocessed_root: words,
    })
}

pub fn run(proving_root: &Path) -> Result<Envelope<TopologyBody>> {
    let mut root = ProvingRoot::open(proving_root)?;
    let privacy_multiverifier_layout = privacy_layout()?;
    let folds = REGISTRIES
        .into_iter()
        .map(|(registry, name)| fold_record(&mut root, registry, name))
        .collect::<Result<Vec<_>>>()?;
    let inputs = root.finish(PINNED_REGISTRIES_SHA256)?;

    let cairo_preprocessed_roots: Vec<CairoRootRecord> =
        goldens::CAIRO_PREPROCESSED_ROOT_LOG_BLOWUPS
            .into_iter()
            .map(cairo_root)
            .collect::<Result<_>>()?;
    for fold in &folds {
        ensure!(
            cairo_preprocessed_roots
                .iter()
                .any(|root| root.log_blowup_factor == fold.cairo_log_blowup_factor),
            "{}: no Cairo root at its log blowup",
            fold.registry
        );
    }

    Ok(Envelope::new(
        "r6",
        "topology",
        inputs,
        TopologyBody {
            privacy_multiverifier_layout,
            folds,
            cairo_preprocessed_roots,
        },
    ))
}
