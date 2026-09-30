//! `fold-tree`: upstream's recursive tree over copies of its golden leaf (rung R9).
//!
//! Runs `stwo_run_and_prove_recursive_tree` (the library entry point of the
//! `stwo_run_and_prove_recursive_tree` binary) on 1, 2, 3, 4 and 5 copies of
//! `test_data/goldens/four_leaves/leaf.json` under `test_data/circuit_registry.json`, as upstream's
//! `dupe_and_fold` does. The four-leaf tree must reproduce the committed goldens byte for byte;
//! the others are recorded: `root_outputs.json` and `root_packed.json` verbatim, `root.proof`
//! (1.5 MB of felt JSON) by length and SHA-256, with the tree's layer and reduction counts.
//!
//! Every reduction proves a 2^23-row multiverifier: 15 in all, about 20 s and 22 GB peak each on
//! an Apple M4 Max.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use circuit_registry::CircuitRegistry;
use serde::Serialize;
use stwo_run_and_prove_recursive_tree::{LeafInput, stwo_run_and_prove_recursive_tree};

use crate::checkpoint::{Envelope, InputRecord, sha256_hex};
use crate::upstream::ProvingRoot;

const REGISTRY: &str = "crates/stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json";
const GOLDENS: &str = "crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves";
const OUTPUTS: [&str; 3] = ["root.proof", "root_outputs.json", "root_packed.json"];
/// Leaf counts folded: a self-fold, one pair, a carry, the goldens' tree, a carry over two layers.
const LEAF_COUNTS: [usize; 5] = [1, 2, 3, 4, 5];
const GOLDEN_LEAF_COUNT: usize = 4;

#[derive(Serialize)]
pub struct ByteRecord {
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct TreeRecord {
    pub n_leaves: usize,
    pub n_layers: usize,
    pub n_pair_reductions: usize,
    pub root_proof: ByteRecord,
    /// `root_outputs.json`, verbatim.
    pub root_outputs: String,
    /// `root_packed.json`, verbatim.
    pub root_packed: String,
}

#[derive(Serialize)]
pub struct FoldTreeBody {
    pub registry: &'static str,
    pub leaf: String,
    pub trees: Vec<TreeRecord>,
}

/// A scratch directory for one tree's root outputs, removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(n_leaves: usize) -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "stwo-circuit-oracle-fold-tree-{}-{n_leaves}",
            std::process::id()
        ));
        std::fs::create_dir(&path)
            .with_context(|| format!("failed to create {}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fold(
    registry: &CircuitRegistry,
    leaf: &LeafInput,
    n_leaves: usize,
) -> Result<(TreeRecord, [Vec<u8>; 3])> {
    let dir = ScratchDir::new(n_leaves)?;
    let paths = OUTPUTS.map(|name| dir.0.join(name));
    let stats = stwo_run_and_prove_recursive_tree(
        vec![leaf.clone(); n_leaves],
        registry,
        &paths[0],
        &paths[1],
        &paths[2],
    )
    .map_err(|error| anyhow::anyhow!("{n_leaves}-leaf tree: {error}"))?;
    ensure!(
        stats.n_leaves == n_leaves,
        "{n_leaves}-leaf tree reports {} leaves",
        stats.n_leaves
    );
    let read = |path: &PathBuf| {
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))
    };
    let files = [read(&paths[0])?, read(&paths[1])?, read(&paths[2])?];
    let record = TreeRecord {
        n_leaves,
        n_layers: stats.n_layers,
        n_pair_reductions: stats.n_pair_reductions,
        root_proof: ByteRecord {
            bytes: files[0].len(),
            sha256: sha256_hex(&files[0]),
        },
        root_outputs: String::from_utf8(files[1].clone())
            .context("root_outputs.json is not UTF-8")?,
        root_packed: String::from_utf8(files[2].clone())
            .context("root_packed.json is not UTF-8")?,
    };
    Ok((record, files))
}

pub fn run(proving_root: &Path) -> Result<Envelope<FoldTreeBody>> {
    let mut root = ProvingRoot::open(proving_root)?;
    let registry: CircuitRegistry = serde_json::from_slice(&root.read(REGISTRY)?)
        .context("failed to parse the recursive-tree registry")?;
    let leaf_path = format!("{GOLDENS}/leaf.json");
    let leaf: LeafInput = serde_json::from_slice(&root.read(&leaf_path)?)
        .context("failed to parse the golden leaf")?;
    let goldens = OUTPUTS
        .map(|name| root.read(&format!("{GOLDENS}/{name}")))
        .into_iter()
        .collect::<Result<Vec<_>>>()?;

    let mut trees = Vec::with_capacity(LEAF_COUNTS.len());
    for n_leaves in LEAF_COUNTS {
        eprintln!("fold-tree: {n_leaves} leaves");
        let (record, files) = fold(&registry, &leaf, n_leaves)?;
        if n_leaves == GOLDEN_LEAF_COUNT {
            for ((name, golden), file) in OUTPUTS.iter().zip(&goldens).zip(&files) {
                ensure!(
                    file == golden,
                    "the {n_leaves}-leaf {name} differs from the committed golden"
                );
            }
        }
        trees.push(record);
    }
    // The registry and the goldens are authenticated against their checked-in copies by
    // `scripts/check_upstream_pins.py`.
    let inputs: Vec<InputRecord> = root.into_records();
    Ok(Envelope::new(
        "r9",
        "fold-tree",
        inputs,
        FoldTreeBody {
            registry: REGISTRY,
            leaf: leaf_path,
            trees,
        },
    ))
}
