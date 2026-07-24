//! Formal retained-production-shape SN3 run-sum A/B.

use blake3::{Hash, Hasher};

use super::sn3_quotient_numerator_bench::{
    assert_canonical_output, capture_canonical_output, input_recipe_digest, poison_outputs,
};
use super::sn3_quotient_retained_fixture::{
    exact_shape, initialize, prepare, retained_image_id, staged_lde_kernel_nodes, upload,
};
use super::sn3_quotient_retained_result::publish_result;
use super::sn3_quotient_topology_fixture::load_sn3_topology_fixture;
use super::*;

pub(crate) const SCHEMA: &str = "stwo.sn3.retained_numerator_to_fri.run_sum_same_object_ab.v1";
pub(crate) const WARMUPS: usize = 3;
pub(crate) const SAMPLES: usize = 20;
pub(crate) const EXPECTED_DIRECT_NODES: u64 = 49;
pub(crate) const EXPECTED_RUN_SUM_NODES: u64 = 66;
const FRI_COPY_CHUNK_WORDS: usize = 1 << 20;

const ORACLE_POISON: u32 = 0x1020_3040;
const EAGER_DIRECT_POISON: u32 = 0x5060_7080;
const EAGER_CANDIDATE_POISON: u32 = 0x90a0_b0c0;
const CAPTURE_DIRECT_POISON: u32 = 0xd0e0_f001;
const CAPTURE_CANDIDATE_POISON: u32 = 0x1234_5678;
const SOURCE_MUTATION_DIRECT_POISON: u32 = 0x89ab_cdef;
const SOURCE_MUTATION_CANDIDATE_POISON: u32 = 0x0f1e_2d3c;
const SOURCE_RESTORE_CANDIDATE_POISON: u32 = 0x4b5a_6978;
const SOURCE_RESTORE_DIRECT_POISON: u32 = 0x8765_4321;
const COEFFICIENT_MUTATION_DIRECT_POISON: u32 = 0x7654_3210;
const COEFFICIENT_MUTATION_CANDIDATE_POISON: u32 = 0xf0e1_d2c3;
const COEFFICIENT_RESTORE_CANDIDATE_POISON: u32 = 0x9687_a5b4;
const COEFFICIENT_RESTORE_DIRECT_POISON: u32 = 0x2143_6587;
const POST_TIMING_DIRECT_POISON: u32 = 0xc3d2_e1f0;
const POST_TIMING_CANDIDATE_POISON: u32 = 0x55aa_33cc;
const RETAINED_IMAGE_POISON: u32 = 0xfeed_5eed;

#[derive(Clone, Copy)]
pub(crate) struct RetainedMutation {
    pub(crate) column: usize,
    pub(crate) source_index: usize,
    pub(crate) source_log_size: u32,
    pub(crate) words: usize,
}

pub(super) fn run() {
    assert_unique_poisons();
    let sn3 = load_sn3_topology_fixture(EXPECTED_SN3_TOPOLOGY_FIXTURE_BLAKE3);
    assert_eq!(sn3.config, EXPECTED_SN3_TOPOLOGY_CONFIG);
    let numerator_recipe = input_recipe_digest(
        &sn3.topology,
        &sn3.requirements,
        &sn3.hybrid,
        &sn3.input_points,
    );
    assert_eq!(
        numerator_recipe.to_hex().as_str(),
        EXPECTED_SN3_INPUT_RECIPE_BLAKE3
    );
    let shape = exact_shape(&sn3.topology);
    let boundary_recipe =
        boundary_input_recipe_digest(numerator_recipe, &shape.quotient_requirements);
    assert_eq!(
        boundary_recipe.to_hex().as_str(),
        EXPECTED_SN3_BOUNDARY_INPUT_RECIPE_BLAKE3
    );
    assert_eq!(staged_lde_kernel_nodes(&shape.retained_requirements), 0);

    let fixture = BenchmarkArena::new(&sn3.topology, &shape);
    assert_eq!(fixture.allocation_bytes, EXPECTED_SN3_ARENA_BYTES);
    assert_eq!(
        fixture.retained_manifest_blake3.to_hex().as_str(),
        EXPECTED_RETAINED_MANIFEST_BLAKE3
    );
    let destinations = fixture.destinations(&shape.control_requirements);
    let oracle_columns = fixture.columns(&sn3.topology, &fixture.source_ids);
    initialize(
        &fixture,
        &sn3.topology,
        &shape,
        &sn3.input_points,
        ORACLE_POISON,
    );

    // The oracle alone materializes all retained FixedImage aliases. It is
    // dropped before the retained descriptor workspace is prepared in place.
    let canonical = {
        let oracle = prepare(
            &fixture,
            &oracle_columns,
            &destinations,
            &fixture.oracle_slots,
            false,
            &[SHARED_STAGED_OVERFLOW],
        );
        assert_eq!(
            oracle.schedule(),
            PreparedNumeratorSchedule::StagedPackedSingleWrite {
                packed_output_rows: 25_165_264,
            }
        );
        oracle.launch().unwrap();
        fixture.arena.context().sync().unwrap();
        capture_canonical_output(&fixture, &shape.control_requirements)
    };
    drop(oracle_columns);

    let retained_columns = fixture.columns(&shape.retained_topology, &fixture.retained_source_ids);
    let prepared = prepare(
        &fixture,
        &retained_columns,
        &destinations,
        &fixture.retained_slots,
        true,
        &[],
    );
    assert_eq!(
        prepared.schedule(),
        PreparedNumeratorSchedule::StagedGroupDirect {
            output_rows: 25_165_264,
        }
    );
    let receipt = prepared
        .group_direct_run_sum_receipt()
        .expect("exact retained SN3 shape must bind run-sum group 0 into victim 12");
    assert_run_sum_receipt(receipt);

    let quotient = PreparedQuotientGraph::prepare(
        &fixture.arena,
        SN3_QUOTIENT_CONFIG,
        &prepared.quotient_sources(),
        fixture.arena.bind(TWIDDLES).unwrap(),
        fixture.arena.bind(INVERSE_TWIDDLES).unwrap(),
        &fixture.quotient_slots,
    )
    .unwrap();
    assert_eq!(
        quotient.output_evaluation().len_words(),
        shape.quotient_requirements.output_value_words
    );

    poison_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        EAGER_DIRECT_POISON,
    );
    prepared.launch_group_direct_baseline().unwrap();
    quotient.launch().unwrap();
    fixture.arena.context().sync().unwrap();
    assert_canonical_output(
        &fixture,
        &shape.retained_requirements,
        &canonical,
        "eager retained direct",
    );
    let canonical_fri = capture_fri_input(&fixture, &quotient);
    assert_exact_bytes(canonical.len_bytes(), canonical_fri.len_bytes());

    poison_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        EAGER_CANDIDATE_POISON,
    );
    prepared.launch().unwrap();
    quotient.launch().unwrap();
    fixture.arena.context().sync().unwrap();
    let eager_candidate = assert_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "eager retained run-sum",
    );

    let capture = fixture.arena.context().capture().unwrap();
    prepared.launch_group_direct_baseline().unwrap();
    quotient.launch().unwrap();
    let direct_graph = capture.finish().unwrap();
    let capture = fixture.arena.context().capture().unwrap();
    prepared.launch().unwrap();
    quotient.launch().unwrap();
    let candidate_graph = capture.finish().unwrap();
    assert_eq!(direct_graph.kernel_nodes(), EXPECTED_DIRECT_NODES);
    assert_eq!(candidate_graph.kernel_nodes(), EXPECTED_RUN_SUM_NODES);
    assert_eq!(
        candidate_graph.kernel_nodes() - direct_graph.kernel_nodes(),
        u64::from(receipt.manifest.run_count)
    );

    poison_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        CAPTURE_DIRECT_POISON,
    );
    direct_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let captured_direct = assert_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "captured retained direct",
    );
    poison_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        CAPTURE_CANDIDATE_POISON,
    );
    candidate_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let captured_candidate = assert_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "captured retained run-sum",
    );

    let mutation = retained_mutation(&shape, receipt);
    let image_id = retained_image_id(mutation.column);
    let original_image = read_slice(&fixture.arena, fixture.arena.bind(image_id).unwrap());
    mutate_source(&fixture, image_id);
    let (source_mutated, source_mutated_fri) = capture_direct_diff(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        &direct_graph,
        &canonical,
        &canonical_fri,
        SOURCE_MUTATION_DIRECT_POISON,
        "retained source-only mutation",
    );
    let source_mutation_candidate = assert_graph_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        &candidate_graph,
        &source_mutated,
        &source_mutated_fri,
        SOURCE_MUTATION_CANDIDATE_POISON,
        "run-sum after retained source-only mutation",
    );
    restore_source(&fixture, image_id, &original_image);
    let (source_restored_candidate, source_restored_direct) = assert_restored_pair(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        &candidate_graph,
        &direct_graph,
        &canonical,
        &canonical_fri,
        SOURCE_RESTORE_CANDIDATE_POISON,
        SOURCE_RESTORE_DIRECT_POISON,
        "retained source restoration",
    );

    mutate_coefficient(&fixture);
    let (coefficient_mutated, coefficient_mutated_fri) = capture_direct_diff(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        &direct_graph,
        &canonical,
        &canonical_fri,
        COEFFICIENT_MUTATION_DIRECT_POISON,
        "random coefficient-only mutation",
    );
    let coefficient_mutation_candidate = assert_graph_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        &candidate_graph,
        &coefficient_mutated,
        &coefficient_mutated_fri,
        COEFFICIENT_MUTATION_CANDIDATE_POISON,
        "run-sum after random coefficient-only mutation",
    );
    restore_coefficient(&fixture);
    let (coefficient_restored_candidate, coefficient_restored_direct) = assert_restored_pair(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        &candidate_graph,
        &direct_graph,
        &canonical,
        &canonical_fri,
        COEFFICIENT_RESTORE_CANDIDATE_POISON,
        COEFFICIENT_RESTORE_DIRECT_POISON,
        "random coefficient restoration",
    );

    for sample in 0..WARMUPS {
        replay_pair(
            sample,
            &direct_graph,
            &candidate_graph,
            fixture.arena.context(),
            None,
        );
    }
    let mut direct_ms = Vec::with_capacity(SAMPLES);
    let mut candidate_ms = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        replay_pair(
            sample,
            &direct_graph,
            &candidate_graph,
            fixture.arena.context(),
            Some((&mut direct_ms, &mut candidate_ms)),
        );
    }

    poison_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        POST_TIMING_DIRECT_POISON,
    );
    direct_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let post_timing_direct = assert_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "post-timing retained direct",
    );
    poison_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        POST_TIMING_CANDIDATE_POISON,
    );
    candidate_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let post_timing_candidate = assert_boundary(
        &fixture,
        &shape.retained_requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "post-timing retained run-sum",
    );

    publish_result(
        &sn3,
        &shape,
        &fixture,
        receipt,
        mutation,
        &canonical,
        &canonical_fri,
        &[
            ("eager_candidate", eager_candidate),
            ("captured_direct", captured_direct),
            ("captured_candidate", captured_candidate),
            (
                "source_mutation_direct",
                (
                    source_mutated.digest().to_owned(),
                    source_mutated_fri.digest,
                ),
            ),
            ("source_mutation_candidate", source_mutation_candidate),
            ("source_restored_candidate", source_restored_candidate),
            ("source_restored_direct", source_restored_direct),
            (
                "coefficient_mutation_direct",
                (
                    coefficient_mutated.digest().to_owned(),
                    coefficient_mutated_fri.digest,
                ),
            ),
            (
                "coefficient_mutation_candidate",
                coefficient_mutation_candidate,
            ),
            (
                "coefficient_restored_candidate",
                coefficient_restored_candidate,
            ),
            ("coefficient_restored_direct", coefficient_restored_direct),
            ("post_timing_direct", post_timing_direct),
            ("post_timing_candidate", post_timing_candidate),
        ],
        direct_ms,
        candidate_ms,
        numerator_recipe,
        boundary_recipe,
    );
}

fn assert_run_sum_receipt(receipt: &stwo_backend_cuda::QuotientNumeratorRunSumReceipt) {
    assert_eq!((receipt.target_group, receipt.victim_group), (0, 12));
    assert_eq!(
        (receipt.target_term_begin, receipt.target_term_end),
        (0, 5_885)
    );
    assert_eq!(
        (receipt.precomputed_term_count, receipt.direct_term_count),
        (5_718, 167)
    );
    assert_eq!(receipt.manifest.run_count, 17);
    assert_eq!(receipt.scratch_words_per_coordinate, 8_388_048);
    assert_eq!(receipt.margin_words_per_coordinate, [560; 4]);
    assert_eq!(receipt.baseline_row_terms, 49_366_958_080);
    assert_eq!(receipt.candidate_add_units, 5_592_751_136);
}

fn retained_mutation(
    shape: &sn3_quotient_retained_fixture::RetainedShape,
    receipt: &stwo_backend_cuda::QuotientNumeratorRunSumReceipt,
) -> RetainedMutation {
    let retained_columns = shape
        .control_plan
        .coefficient_ldes()
        .iter()
        .map(|lde| lde.column())
        .collect::<std::collections::BTreeSet<_>>();
    receipt
        .manifest
        .active_entries()
        .iter()
        .flat_map(|entry| {
            (entry.term_begin as usize..entry.term_end as usize).map(move |term| (entry, term))
        })
        .filter_map(|(entry, term)| {
            let source_index = shape.retained_plan.term_descriptors()[term * 3] as usize;
            let source = shape.retained_plan.sources()[source_index];
            retained_columns
                .contains(&source.column())
                .then_some(RetainedMutation {
                    column: source.column(),
                    source_index,
                    source_log_size: entry.source_log_size,
                    words: 1usize << entry.source_log_size,
                })
        })
        .min_by_key(|candidate| (candidate.words, candidate.column))
        .expect("run-sum prefix must consume at least one retained FixedImage evaluation")
}

fn mutate_source(fixture: &BenchmarkArena, image_id: ArenaSlotId) {
    let image = fixture.arena.bind(image_id).unwrap();
    unsafe {
        fixture
            .arena
            .context()
            .fill_u32_async(image.as_u32_ptr(), RETAINED_IMAGE_POISON, image.len_words())
            .unwrap();
    }
    fixture.arena.context().sync().unwrap();
}

fn restore_source(fixture: &BenchmarkArena, image_id: ArenaSlotId, image: &[u32]) {
    upload(&fixture.arena, image_id, image);
}

fn mutate_coefficient(fixture: &BenchmarkArena) {
    upload(
        &fixture.arena,
        RANDOM_COEFFICIENT,
        &secure_words(&[SecureField::from_u32_unchecked(331, 337, 347, 349)]),
    );
}

fn restore_coefficient(fixture: &BenchmarkArena) {
    upload(
        &fixture.arena,
        RANDOM_COEFFICIENT,
        &secure_words(&[random_coefficient()]),
    );
}

#[allow(clippy::too_many_arguments)]
fn capture_direct_diff(
    fixture: &BenchmarkArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    quotient: &PreparedQuotientGraph<'_>,
    direct_graph: &CudaGraphExec,
    canonical: &sn3_quotient_numerator_bench::CanonicalOutput,
    canonical_fri: &CanonicalFriInput,
    poison: u32,
    label: &str,
) -> (
    sn3_quotient_numerator_bench::CanonicalOutput,
    CanonicalFriInput,
) {
    poison_boundary(fixture, requirements, quotient, poison);
    direct_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let numerator = capture_canonical_output(fixture, requirements);
    let fri = capture_fri_input(fixture, quotient);
    assert_ne!(
        numerator.digest(),
        canonical.digest(),
        "{label}: direct numerator did not change"
    );
    assert_ne!(
        fri.digest, canonical_fri.digest,
        "{label}: direct FRI input did not change"
    );
    (numerator, fri)
}

#[allow(clippy::too_many_arguments)]
fn assert_graph_boundary(
    fixture: &BenchmarkArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    quotient: &PreparedQuotientGraph<'_>,
    graph: &CudaGraphExec,
    expected: &sn3_quotient_numerator_bench::CanonicalOutput,
    expected_fri: &CanonicalFriInput,
    poison: u32,
    label: &str,
) -> (Hash, Hash) {
    poison_boundary(fixture, requirements, quotient, poison);
    graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    assert_boundary(
        fixture,
        requirements,
        quotient,
        expected,
        expected_fri,
        label,
    )
}

#[allow(clippy::too_many_arguments)]
fn assert_restored_pair(
    fixture: &BenchmarkArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    quotient: &PreparedQuotientGraph<'_>,
    candidate_graph: &CudaGraphExec,
    direct_graph: &CudaGraphExec,
    canonical: &sn3_quotient_numerator_bench::CanonicalOutput,
    canonical_fri: &CanonicalFriInput,
    candidate_poison: u32,
    direct_poison: u32,
    label: &str,
) -> ((Hash, Hash), (Hash, Hash)) {
    let candidate = assert_graph_boundary(
        fixture,
        requirements,
        quotient,
        candidate_graph,
        canonical,
        canonical_fri,
        candidate_poison,
        &format!("{label} candidate"),
    );
    let direct = assert_graph_boundary(
        fixture,
        requirements,
        quotient,
        direct_graph,
        canonical,
        canonical_fri,
        direct_poison,
        &format!("{label} direct"),
    );
    (candidate, direct)
}

fn poison_boundary(
    fixture: &BenchmarkArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    quotient: &PreparedQuotientGraph<'_>,
    poison: u32,
) {
    poison_outputs(fixture, requirements, poison);
    let output = quotient.output_evaluation();
    unsafe {
        fixture
            .arena
            .context()
            .fill_u32_async(output.as_u32_ptr(), !poison, output.len_words())
            .unwrap();
    }
    fixture.arena.context().sync().unwrap();
}

fn assert_boundary(
    fixture: &BenchmarkArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    quotient: &PreparedQuotientGraph<'_>,
    expected: &sn3_quotient_numerator_bench::CanonicalOutput,
    expected_fri: &CanonicalFriInput,
    label: &str,
) -> (Hash, Hash) {
    (
        assert_canonical_output(fixture, requirements, expected, label),
        assert_fri_input(fixture, quotient, expected_fri, label),
    )
}

fn replay_pair(
    sample: usize,
    direct: &CudaGraphExec,
    candidate: &CudaGraphExec,
    context: &CudaExecContext,
    samples: Option<(&mut Vec<f64>, &mut Vec<f64>)>,
) {
    let (first, second) = if sample % 2 == 0 {
        (direct, candidate)
    } else {
        (candidate, direct)
    };
    let first_ms = replay_cuda_ms(first, context);
    let second_ms = replay_cuda_ms(second, context);
    if let Some((direct_ms, candidate_ms)) = samples {
        if sample % 2 == 0 {
            direct_ms.push(first_ms);
            candidate_ms.push(second_ms);
        } else {
            candidate_ms.push(first_ms);
            direct_ms.push(second_ms);
        }
    }
}

fn replay_cuda_ms(graph: &CudaGraphExec, context: &CudaExecContext) -> f64 {
    assert!(context.begin_timing().unwrap() >= 1);
    graph.launch(context).unwrap();
    context.mark_timing().unwrap();
    context.sync().unwrap();
    f64::from(context.elapsed_timing_ms(1).unwrap()[0])
}

pub(crate) struct CanonicalFriInput {
    pub(crate) words: Vec<u32>,
    pub(crate) digest: Hash,
}

impl CanonicalFriInput {
    pub(crate) fn len_bytes(&self) -> u64 {
        u64::try_from(self.words.len()).unwrap() * 4
    }
}

fn capture_fri_input(
    fixture: &BenchmarkArena,
    quotient: &PreparedQuotientGraph<'_>,
) -> CanonicalFriInput {
    let words = read_slice(&fixture.arena, quotient.output_evaluation());
    let digest = fri_digest(&words);
    CanonicalFriInput { words, digest }
}

fn assert_fri_input(
    fixture: &BenchmarkArena,
    quotient: &PreparedQuotientGraph<'_>,
    expected: &CanonicalFriInput,
    label: &str,
) -> Hash {
    let actual = read_slice(&fixture.arena, quotient.output_evaluation());
    assert_eq!(actual, expected.words, "{label}: FRI input differs");
    let digest = fri_digest(&actual);
    assert_eq!(digest, expected.digest, "{label}: FRI digest differs");
    digest
}

fn read_slice(arena: &DeviceArena, source: ArenaSlice) -> Vec<u32> {
    let mut words = Vec::with_capacity(source.len_words());
    for offset in (0..source.len_words()).step_by(FRI_COPY_CHUNK_WORDS) {
        let count = FRI_COPY_CHUNK_WORDS.min(source.len_words() - offset);
        let mut chunk = vec![0u32; count];
        unsafe {
            arena
                .context()
                .memcpy_d2h_async(
                    chunk.as_mut_ptr().cast(),
                    source.as_u32_ptr().add(offset).cast(),
                    count * 4,
                )
                .unwrap();
        }
        arena.context().sync().unwrap();
        words.extend(chunk);
    }
    words
}

fn fri_digest(words: &[u32]) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(b"stwo.sn3-quotient-fri-input.output.v1\0");
    hasher.update(&u64::try_from(words.len()).unwrap().to_le_bytes());
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    hasher.finalize()
}

fn assert_exact_bytes(numerator: u64, fri: u64) {
    assert_eq!(numerator, 402_645_136);
    assert_eq!(fri, FRI_INPUT_OUTPUT_BYTES);
}

fn assert_unique_poisons() {
    let poisons = [
        ORACLE_POISON,
        EAGER_DIRECT_POISON,
        EAGER_CANDIDATE_POISON,
        CAPTURE_DIRECT_POISON,
        CAPTURE_CANDIDATE_POISON,
        SOURCE_MUTATION_DIRECT_POISON,
        SOURCE_MUTATION_CANDIDATE_POISON,
        SOURCE_RESTORE_CANDIDATE_POISON,
        SOURCE_RESTORE_DIRECT_POISON,
        COEFFICIENT_MUTATION_DIRECT_POISON,
        COEFFICIENT_MUTATION_CANDIDATE_POISON,
        COEFFICIENT_RESTORE_CANDIDATE_POISON,
        COEFFICIENT_RESTORE_DIRECT_POISON,
        POST_TIMING_DIRECT_POISON,
        POST_TIMING_CANDIDATE_POISON,
        RETAINED_IMAGE_POISON,
    ];
    for (index, poison) in poisons.iter().enumerate() {
        assert!(!poisons[index + 1..].contains(poison));
    }
}

fn boundary_input_recipe_digest(
    numerator_recipe: Hash,
    requirements: &QuotientWorkspaceRequirements,
) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(b"stwo.sn3-numerator-to-fri-input.input-recipe.v2\0");
    hasher.update(numerator_recipe.as_bytes());
    hasher.update(&u64::try_from(GROUP_LOGS.len()).unwrap().to_le_bytes());
    for log_size in GROUP_LOGS {
        hasher.update(&u64::from(log_size).to_le_bytes());
    }
    let pass = requirements.combine_pass_bytes;
    let fields = [
        u64::from(requirements.config.lifting_log_size),
        u64::from(requirements.config.log_blowup_factor),
        u64::from(requirements.subdomain_log_size),
        u64::try_from(requirements.sample_count).unwrap(),
        u64::try_from(requirements.sample_point_words).unwrap(),
        u64::try_from(requirements.first_linear_term_words).unwrap(),
        u64::try_from(requirements.partial_log_size_words).unwrap(),
        u64::try_from(requirements.partial_pointer_words).unwrap(),
        u64::try_from(requirements.coordinate_pointer_words).unwrap(),
        u64::try_from(requirements.coefficient_size_words).unwrap(),
        u64::try_from(requirements.subdomain_value_words).unwrap(),
        u64::try_from(requirements.output_value_words).unwrap(),
        u64::try_from(pass.rows).unwrap(),
        u64::try_from(pass.samples).unwrap(),
        u64::try_from(pass.denominator_inversions).unwrap(),
        u64::try_from(pass.eliminated_scratch_bytes).unwrap(),
        u64::try_from(pass.eliminated_logical_traffic_bytes).unwrap(),
        u64::try_from(pass.denominator_global_passes).unwrap(),
        u64::try_from(pass.output_write_bytes).unwrap(),
        u64::try_from(requirements.forward_twiddle_words).unwrap(),
        u64::try_from(requirements.inverse_twiddle_words).unwrap(),
        u64::from(requirements.half_coset_initial_index),
        u64::from(requirements.half_coset_step_size),
        INVERSE_TWIDDLE_PATTERN_SEED,
    ];
    hasher.update(&u64::try_from(fields.len()).unwrap().to_le_bytes());
    for value in fields {
        hasher.update(&value.to_le_bytes());
    }
    hasher.finalize()
}
