//! Machine-readable result and promotion envelope for the retained SN3 A/B.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use blake3::{Hash, Hasher};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::sn3_quotient_numerator_bench::{artifact_identity, percentile};
use super::sn3_quotient_retained_fixture::staged_lde_kernel_nodes;
use super::sn3_quotient_retained_run_sum_ab::{
    CanonicalFriInput, RetainedMutation, EXPECTED_DIRECT_NODES, EXPECTED_RUN_SUM_NODES, SAMPLES,
    SCHEMA, WARMUPS,
};
use super::*;

const SEALED_A40_RETAINED_P50_MS: f64 = 335.177_948;
const SEALED_A40_RETAINED_P95_MS: f64 = 336.626_038;
const THREE_X_RETAINED_MAX_MS: f64 = 144.268;
const FIVE_X_RETAINED_MAX_MS: f64 = 106.086;
const STATIC_SASS_RECEIPT_ENV: &str = "STWO_SN3_RETAINED_RUN_SUM_STATIC_SASS_RECEIPT";
const STATIC_SASS_SCHEMA: &str = "stwo.cuda.retained_run_sum.static_sass.v1";
const STATIC_SASS_DLINK_MEMBER: &str = "stwo_cuda_kernels_dlink.staged.o";
const STATIC_SASS_ELF: &str = "lto.sm_86.cubin";
const CUOBJDUMP_PATH: &str = "/usr/local/cuda/bin/cuobjdump";
const CUDA_VERSION_MARKER: &str = "Cuda compilation tools, release 13.3";
const RUN_PRECOMPUTE_KERNEL: &str = "stwo_quotient_numerator_native_run_precompute_kernel";
const RUN_SUM_EXPAND_KERNEL: &str = "stwo_quotient_numerator_run_sum_expand_kernel";
const EXACT_NUMERATOR_AND_AUXILIARY_BYTES: u64 = 402_645_136;
const REQUIRED_EXACT_DIGESTS: usize = 13;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticSassReceipt {
    schema: String,
    passed: bool,
    archive: StaticSassArchive,
    tool: StaticSassTool,
    target: StaticSassTarget,
    kernels: BTreeMap<String, StaticSassKernel>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticSassArchive {
    sha256: String,
    dlink_member: String,
    dlink_sha256: String,
    sibling_sha256: String,
    member_matches_sibling: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticSassTool {
    cuobjdump_path: String,
    cuobjdump_sha256: String,
    version: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticSassTarget {
    elf_count: u32,
    elf: String,
    sms: Vec<u32>,
    ptx_files: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticSassKernel {
    resource_definitions: u32,
    sass_definitions: u32,
    registers: u32,
    stack_bytes: u64,
    shared_bytes: u64,
    local_bytes: u64,
    ldl: u64,
    stl: u64,
    call: u64,
    jcal: u64,
    sm86_flag_occurrences: u64,
}

struct StaticSassEvidence {
    path: PathBuf,
    raw_blake3: Hash,
    receipt: StaticSassReceipt,
    validated: bool,
}

struct AotPackEvidence {
    identity: Hash,
    entries: usize,
    entries_for_sm86: usize,
    supports_sm86: bool,
    manifest_hash: u64,
    constraint_max_instrs: usize,
    constraint_max_live_u32_lanes: usize,
    validated: bool,
}

pub(crate) fn assert_promotion_artifacts() {
    assert_eq!(
        option_env!("STWO_CUDA_ARCHIVE_LTO"),
        Some("1"),
        "formal retained A/B requires archive LTO"
    );
    let artifact = artifact_identity();
    assert!(
        artifact.is_complete(),
        "formal retained A/B requires complete CUDA artifact identity"
    );
    assert!(
        load_static_sass_receipt(artifact.boundary_cuda_module_sha256()).validated,
        "formal retained A/B requires validated static SASS"
    );
    assert!(
        aot_pack_evidence().validated,
        "formal retained A/B requires a validated nonempty SM86 AOT pack"
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_result(
    sn3: &sn3_quotient_topology_fixture::LoadedTopologyFixture,
    shape: &sn3_quotient_retained_fixture::RetainedShape,
    fixture: &BenchmarkArena,
    receipt: &stwo_backend_cuda::QuotientNumeratorRunSumReceipt,
    mutation: RetainedMutation,
    canonical: &sn3_quotient_numerator_bench::CanonicalOutput,
    canonical_fri: &CanonicalFriInput,
    digests: &[(&str, (Hash, Hash))],
    direct_ms: Vec<f64>,
    candidate_ms: Vec<f64>,
    numerator_recipe: Hash,
    boundary_recipe: Hash,
) {
    let direct_p50 = percentile(&direct_ms, 50);
    let direct_p95 = percentile(&direct_ms, 95);
    let candidate_p50 = percentile(&candidate_ms, 50);
    let candidate_p95 = percentile(&candidate_ms, 95);
    let artifact = artifact_identity();
    let measurement_source = retained_measurement_source_digest();
    let archive_lto_requested = option_env!("STWO_CUDA_ARCHIVE_LTO") == Some("1");
    let artifact_eligible =
        archive_lto_requested && artifact.cuda_build_mode == "cuda" && artifact.is_complete();
    let exact_sample_count = direct_ms.len() == SAMPLES && candidate_ms.len() == SAMPLES;
    let paired_candidate_wins = direct_ms
        .iter()
        .zip(&candidate_ms)
        .filter(|(direct, candidate)| candidate < direct)
        .count();
    let all_pairs_won = exact_sample_count && paired_candidate_wins == SAMPLES;
    let p95_non_regression = candidate_p95 <= direct_p95;
    let canonical_pair = (*canonical.digest(), canonical_fri.digest);
    let source_direct = required_digest(digests, "source_mutation_direct");
    let source_candidate = required_digest(digests, "source_mutation_candidate");
    let coefficient_direct = required_digest(digests, "coefficient_mutation_direct");
    let coefficient_candidate = required_digest(digests, "coefficient_mutation_candidate");
    let canonical_labels = [
        "eager_candidate",
        "captured_direct",
        "captured_candidate",
        "source_restored_candidate",
        "source_restored_direct",
        "coefficient_restored_candidate",
        "coefficient_restored_direct",
        "post_timing_direct",
        "post_timing_candidate",
    ];
    let exact_checks_passed = digests.len() == REQUIRED_EXACT_DIGESTS
        && canonical.len_bytes() == EXACT_NUMERATOR_AND_AUXILIARY_BYTES
        && canonical_fri.len_bytes() == FRI_INPUT_OUTPUT_BYTES
        && canonical_labels
            .iter()
            .all(|label| required_digest(digests, label) == &canonical_pair)
        && source_direct == source_candidate
        && source_direct.0 != canonical_pair.0
        && source_direct.1 != canonical_pair.1
        && coefficient_direct == coefficient_candidate
        && coefficient_direct.0 != canonical_pair.0
        && coefficient_direct.1 != canonical_pair.1;
    assert!(exact_checks_passed, "formal exact-check gate failed");
    let static_sass = load_static_sass_receipt(artifact.boundary_cuda_module_sha256());
    let static_sass_gate_passed = static_sass.validated;
    let aot_pack = aot_pack_evidence();
    let formal_promotion_eligible = artifact_eligible
        && all_pairs_won
        && p95_non_regression
        && exact_checks_passed
        && static_sass_gate_passed
        && aot_pack.validated;
    let result = json!({
        "schema": SCHEMA,
        "passed": true,
        "result_class": "observed retained-production-shape same-prepared-object A/B; not an end-to-end proof MHz claim",
        "timing_scope": "retained FixedImage numerator plus unchanged ordinary quotient-to-FRI-input, CUDA-event device elapsed",
        "baseline": "retained_group_direct",
        "candidate": "retained_native_domain_run_sum_group0_victim_group12",
        "prepared_ownership": {
            "timed_retained_numerator_objects": 1,
            "same_prepared_object": true,
            "oracle_dropped_before_retained_prepare": true,
            "cold_fixed_image_materialization_in_timing": false,
        },
        "fixed_image": {
            "retained_evaluation_count": RETAINED_COLUMN_COUNT,
            "retained_words": RETAINED_IMAGE_WORDS,
            "retained_bytes": RETAINED_IMAGE_WORDS as u64 * 4,
            "manifest_blake3": fixture.retained_manifest_blake3.to_string(),
            "staged_coefficient_sources": 0,
            "staged_lde_kernel_nodes": staged_lde_kernel_nodes(&shape.retained_requirements),
        },
        "bytes": {
            "validated_numerator_and_auxiliary": canonical.len_bytes(),
            "validated_fri_input": canonical_fri.len_bytes(),
            "exact_word_comparison": true,
            "poisoned_complete_writes": true,
        },
        "plan": {
            "identity_blake3": Hash::from_bytes(receipt.identity).to_string(),
            "target_group": receipt.target_group,
            "victim_group": receipt.victim_group,
            "run_count": receipt.manifest.run_count,
            "precomputed_terms": receipt.precomputed_term_count,
            "direct_terms": receipt.direct_term_count,
            "scratch_words_per_coordinate": receipt.scratch_words_per_coordinate,
            "margin_words_per_coordinate": receipt.margin_words_per_coordinate,
            "incremental_arena_bytes": 0,
            "baseline_row_terms": receipt.baseline_row_terms,
            "candidate_add_units": receipt.candidate_add_units,
        },
        "checks": {
            "eager_candidate_exact": true,
            "captured_direct_exact": true,
            "captured_candidate_exact": true,
            "retained_source_only_direct_diff": true,
            "retained_source_only_candidate_full_byte_exact": true,
            "retained_source_restoration_candidate_exact": true,
            "retained_source_restoration_direct_exact": true,
            "random_coefficient_only_direct_diff": true,
            "random_coefficient_only_candidate_full_byte_exact": true,
            "random_coefficient_restoration_candidate_exact": true,
            "random_coefficient_restoration_direct_exact": true,
            "post_timing_direct_exact": true,
            "post_timing_candidate_exact": true,
            "formal_exact_check_gate": exact_checks_passed,
        },
        "mutation": {
            "retained_column": mutation.column,
            "source_index": mutation.source_index,
            "source_log_size": mutation.source_log_size,
            "image_words": mutation.words,
            "run_sum_consumed": true,
            "phases": ["retained_source_only", "random_coefficient_only"],
            "each_phase_restored_before_next_phase": true,
        },
        "digests": {
            "canonical_numerator_blake3": canonical.digest().to_string(),
            "canonical_fri_blake3": canonical_fri.digest.to_string(),
            "validated": digests.iter().map(|(label, (numerator, fri))| {
                ((*label).to_owned(), json!({
                    "numerator_blake3": numerator.to_string(),
                    "fri_blake3": fri.to_string(),
                }))
            }).collect::<serde_json::Map<_, _>>(),
        },
        "graph": {
            "direct_kernel_nodes": EXPECTED_DIRECT_NODES,
            "candidate_kernel_nodes": EXPECTED_RUN_SUM_NODES,
            "candidate_minus_direct": EXPECTED_RUN_SUM_NODES - EXPECTED_DIRECT_NODES,
            "expected_delta_from_run_count": receipt.manifest.run_count,
        },
        "timing": {
            "ordering": "AB,BA alternating",
            "warmups_each": WARMUPS,
            "samples_each": SAMPLES,
            "percentile_method": "nearest-rank",
            "direct_samples_ms": direct_ms,
            "candidate_samples_ms": candidate_ms,
            "direct": {"p50_ms": direct_p50, "p95_ms": direct_p95},
            "candidate": {"p50_ms": candidate_p50, "p95_ms": candidate_p95},
            "speedup": {"p50": direct_p50 / candidate_p50, "p95": direct_p95 / candidate_p95},
        },
        "objective_reward": {
            "reference": {
                "sealed_a40_retained_p50_ms": SEALED_A40_RETAINED_P50_MS,
                "sealed_a40_retained_p95_ms": SEALED_A40_RETAINED_P95_MS,
            },
            "observed": {
                "p50_saved_ms": direct_p50 - candidate_p50,
                "p95_saved_ms": direct_p95 - candidate_p95,
                "positive_p50": candidate_p50 < direct_p50,
                "positive_p95": candidate_p95 < direct_p95,
            },
            "diagnostic_thresholds": {
                "three_x_boundary_max_ms": THREE_X_RETAINED_MAX_MS,
                "five_x_boundary_max_ms": FIVE_X_RETAINED_MAX_MS,
                "diagnostic_three_x": candidate_p50 <= THREE_X_RETAINED_MAX_MS,
                "diagnostic_five_x": candidate_p50 <= FIVE_X_RETAINED_MAX_MS,
            },
        },
        "artifact_eligibility": {
            "eligible": artifact_eligible,
            "requires": "CUDA archive-LTO request and complete linked-module artifact identity",
            "archive_lto_requested_at_compile": archive_lto_requested,
            "cuda_build_mode": artifact.cuda_build_mode,
            "identity_complete": artifact.is_complete(),
        },
        "static_sass_evidence": {
            "receipt_env": STATIC_SASS_RECEIPT_ENV,
            "receipt_path": static_sass.path,
            "receipt_blake3": static_sass.raw_blake3.to_string(),
            "schema": static_sass.receipt.schema,
            "passed": static_sass.receipt.passed,
            "archive": static_sass.receipt.archive,
            "tool": static_sass.receipt.tool,
            "target": static_sass.receipt.target,
            "kernels": static_sass.receipt.kernels,
            "validated": static_sass_gate_passed,
            "required_for_formal_promotion": true,
        },
        "aot_pack_evidence": {
            "identity": aot_pack.identity.to_string(),
            "entries": aot_pack.entries,
            "entries_for_sm86": aot_pack.entries_for_sm86,
            "supports_sm86": aot_pack.supports_sm86,
            "manifest_hash": aot_pack.manifest_hash,
            "constraint_bounds": {
                "max_instrs": aot_pack.constraint_max_instrs,
                "max_live_u32_lanes": aot_pack.constraint_max_live_u32_lanes,
            },
            "validated": aot_pack.validated,
            "required_for_formal_promotion": true,
        },
        "formal_promotion": {
            "eligible": formal_promotion_eligible,
            "requires": "artifact eligibility, 20/20 paired candidate wins, p95 non-regression, exact-output checks, validated static-SASS receipt, and validated nonempty sm_86 AOT pack",
            "required_paired_candidate_wins": SAMPLES,
            "observed_paired_candidate_wins": paired_candidate_wins,
            "exact_sample_count": exact_sample_count,
            "all_pairs_won": all_pairs_won,
            "p95_non_regression": p95_non_regression,
            "exact_checks_passed": exact_checks_passed,
            "validated_static_sass_receipt": static_sass_gate_passed,
            "validated_aot_pack": aot_pack.validated,
            "three_x_boundary_max_ms": THREE_X_RETAINED_MAX_MS,
            "five_x_boundary_max_ms": FIVE_X_RETAINED_MAX_MS,
            "passes_three_x": formal_promotion_eligible && candidate_p50 <= THREE_X_RETAINED_MAX_MS,
            "passes_five_x": formal_promotion_eligible && candidate_p50 <= FIVE_X_RETAINED_MAX_MS,
        },
        "identity": {
            "topology_fixture_blake3": sn3.digest.to_string(),
            "numerator_input_recipe_blake3": numerator_recipe.to_string(),
            "boundary_input_recipe_blake3": boundary_recipe.to_string(),
            "retained_measurement_source_blake3": measurement_source.to_string(),
            "base_boundary_seal_blake3": artifact.boundary_seal_blake3.to_string(),
            "boundary_source_projection_sha256": artifact.boundary_source_projection_sha256(),
            "boundary_cuda_module_sha256": artifact.boundary_cuda_module_sha256(),
            "ordinary_cuda_source_blake3": artifact.ordinary_cuda_source_blake3.to_string(),
            "test_binary_blake3": artifact.test_binary_blake3.to_string(),
            "cuda_build_mode": artifact.cuda_build_mode,
            "archive_lto_requested_at_compile": archive_lto_requested,
            "expected_cuda_module_build_identity": artifact.expected_cuda_module_build_identity.to_string(),
            "linked_cuda_module_build_identity": artifact.linked_cuda_module_build_identity.to_string(),
            "cuda_module_target_sms": artifact.cuda_module_target_sms,
            "identity_complete": artifact.is_complete(),
        },
    });
    publish(&result);
}

fn required_digest<'a>(
    digests: &'a [(&str, (Hash, Hash))],
    required_label: &str,
) -> &'a (Hash, Hash) {
    &digests
        .iter()
        .find(|(label, _)| *label == required_label)
        .unwrap_or_else(|| panic!("missing exact-check digest {required_label}"))
        .1
}

fn load_static_sass_receipt(expected_archive_sha256: Option<&str>) -> StaticSassEvidence {
    let expected_archive_sha256 = expected_archive_sha256
        .expect("static-SASS receipt requires the linked CUDA archive SHA-256 identity");
    let path = std::env::var_os(STATIC_SASS_RECEIPT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{STATIC_SASS_RECEIPT_ENV} is required"));
    let raw = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let receipt: StaticSassReceipt = serde_json::from_slice(&raw)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    assert_eq!(receipt.schema, STATIC_SASS_SCHEMA, "static-SASS schema");
    assert!(receipt.passed, "static-SASS producer did not pass");
    assert_sha256("archive.sha256", &receipt.archive.sha256);
    assert_sha256("archive.dlink_sha256", &receipt.archive.dlink_sha256);
    assert_sha256("archive.sibling_sha256", &receipt.archive.sibling_sha256);
    assert_sha256("tool.cuobjdump_sha256", &receipt.tool.cuobjdump_sha256);
    assert_eq!(
        receipt.archive.sha256, expected_archive_sha256,
        "static-SASS archive does not match the linked CUDA module"
    );
    assert_eq!(
        receipt.archive.dlink_member, STATIC_SASS_DLINK_MEMBER,
        "static-SASS dlink member"
    );
    assert!(
        receipt.archive.member_matches_sibling,
        "static-SASS dlink member was not matched to the published sibling"
    );
    assert_eq!(
        receipt.archive.dlink_sha256, receipt.archive.sibling_sha256,
        "static-SASS dlink and sibling SHA-256 differ"
    );
    assert_eq!(
        receipt.tool.cuobjdump_path, CUOBJDUMP_PATH,
        "static-SASS cuobjdump path"
    );
    assert!(
        !receipt.tool.version.is_empty() && receipt.tool.version.contains(CUDA_VERSION_MARKER),
        "static-SASS cuobjdump version must contain {CUDA_VERSION_MARKER}"
    );
    assert_eq!(receipt.target.elf_count, 1, "static-SASS ELF count");
    assert_eq!(receipt.target.elf, STATIC_SASS_ELF, "static-SASS ELF name");
    assert_eq!(
        receipt.target.sms.as_slice(),
        &[86],
        "static-SASS target SMs"
    );
    assert_eq!(receipt.target.ptx_files, 0, "static-SASS PTX file count");
    assert_eq!(receipt.kernels.len(), 2, "static-SASS kernel map size");
    validate_static_sass_kernel(
        RUN_PRECOMPUTE_KERNEL,
        receipt
            .kernels
            .get(RUN_PRECOMPUTE_KERNEL)
            .unwrap_or_else(|| panic!("missing static-SASS kernel {RUN_PRECOMPUTE_KERNEL}")),
        38,
    );
    validate_static_sass_kernel(
        RUN_SUM_EXPAND_KERNEL,
        receipt
            .kernels
            .get(RUN_SUM_EXPAND_KERNEL)
            .unwrap_or_else(|| panic!("missing static-SASS kernel {RUN_SUM_EXPAND_KERNEL}")),
        40,
    );
    StaticSassEvidence {
        path,
        raw_blake3: blake3::hash(&raw),
        receipt,
        validated: true,
    }
}

fn assert_sha256(label: &str, value: &str) {
    assert!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{label} must be a lowercase 64-character SHA-256"
    );
}

fn validate_static_sass_kernel(name: &str, kernel: &StaticSassKernel, registers: u32) {
    assert_eq!(
        kernel.resource_definitions, 1,
        "{name} resource definitions"
    );
    assert_eq!(kernel.sass_definitions, 1, "{name} SASS definitions");
    assert_eq!(kernel.registers, registers, "{name} registers");
    assert_eq!(kernel.stack_bytes, 0, "{name} stack bytes");
    assert_eq!(kernel.shared_bytes, 0, "{name} shared bytes");
    assert_eq!(kernel.local_bytes, 0, "{name} local bytes");
    assert_eq!(kernel.ldl, 0, "{name} LDL instructions");
    assert_eq!(kernel.stl, 0, "{name} STL instructions");
    assert_eq!(kernel.call, 0, "{name} CALL instructions");
    assert_eq!(kernel.jcal, 0, "{name} JCAL instructions");
    assert!(
        kernel.sm86_flag_occurrences >= 1,
        "{name} lacks an sm_86 header flag"
    );
}

fn aot_pack_evidence() -> AotPackEvidence {
    use stwo_backend_cuda_kernels::aot_pack;

    let identity_bytes = aot_pack::aot_pack_identity();
    let entries = aot_pack::aot_pack_entries();
    let entries_for_sm86 = aot_pack::aot_pack_entries_for_arch(8, 6);
    let supports_sm86 = aot_pack::aot_pack_supports_arch(8, 6);
    let manifest_hash = aot_pack::aot_pack_manifest_hash();
    let constraint_max_instrs = aot_pack::aot_pack_constraint_max_instrs();
    let constraint_max_live_u32_lanes = aot_pack::aot_pack_constraint_max_live_u32_lanes();
    let validated = identity_bytes != [0; 32]
        && entries > 0
        && entries_for_sm86 == entries
        && supports_sm86
        && manifest_hash != 0
        && constraint_max_instrs > 0
        && constraint_max_live_u32_lanes > 0;
    AotPackEvidence {
        identity: Hash::from_bytes(identity_bytes),
        entries,
        entries_for_sm86,
        supports_sm86,
        manifest_hash,
        constraint_max_instrs,
        constraint_max_live_u32_lanes,
        validated,
    }
}

fn retained_measurement_source_digest() -> Hash {
    let sources: &[(&str, &[u8])] = &[
        (
            "tests/prepared_quotient_numerator_sn3_retained_run_sum_native.rs",
            include_bytes!("../prepared_quotient_numerator_sn3_retained_run_sum_native.rs"),
        ),
        (
            "tests/support/sn3_quotient_retained_fixture.rs",
            include_bytes!("sn3_quotient_retained_fixture.rs"),
        ),
        (
            "tests/support/sn3_quotient_retained_run_sum_ab.rs",
            include_bytes!("sn3_quotient_retained_run_sum_ab.rs"),
        ),
        (
            "tests/support/sn3_quotient_retained_result.rs",
            include_bytes!("sn3_quotient_retained_result.rs"),
        ),
        (
            "src/backend/quotient_numerator_run_sum.rs",
            include_bytes!("../../src/backend/quotient_numerator_run_sum.rs"),
        ),
        (
            "src/backend/prepared_quotient_numerator/run_sum.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/run_sum.rs"),
        ),
        (
            "cuda/quotient_numerator_native_run_sum.cu",
            include_bytes!(
                "../../../backend-cuda-kernels/cuda/quotient_numerator_native_run_sum.cu"
            ),
        ),
    ];
    let mut hasher = Hasher::new();
    hasher.update(b"stwo.sn3.retained-run-sum.measurement-sources.v1\0");
    for (name, bytes) in sources {
        hasher.update(&u64::try_from(name.len()).unwrap().to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(&u64::try_from(bytes.len()).unwrap().to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finalize()
}

fn publish(receipt: &serde_json::Value) {
    let bytes = serde_json::to_vec_pretty(receipt).unwrap();
    if let Some(path) = std::env::var_os("STWO_SN3_RETAINED_RUN_SUM_AB_RECEIPT").map(PathBuf::from)
    {
        assert!(!path.exists(), "refusing to replace {}", path.display());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();
        fs::rename(temporary, path).unwrap();
    }
    println!(
        "STWO_SN3_RETAINED_RUN_SUM_AB_RECEIPT_JSON={}",
        serde_json::to_string(receipt).unwrap()
    );
}
