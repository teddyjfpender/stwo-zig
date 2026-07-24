use std::fs::File;
use std::io::Read;

use blake3::{Hash, Hasher};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo_backend_cuda::{
    ArenaSlice, ArenaSlotId, DeviceArena, QuotientNumeratorColumnTopology,
    QuotientNumeratorHybridPlan, QuotientNumeratorSourceKind,
    QuotientNumeratorWorkspaceRequirements,
};

use super::{
    oods_values, point_words, random_coefficient, secure_words, source_words, BenchmarkArena,
    FIRST_TERMS_OUTPUT, SAMPLE_POINTS_OUTPUT,
};

const COPY_CHUNK_WORDS: usize = 1 << 20;
const PATTERN_CHUNK_WORDS: usize = 1 << 22;
const OUTPUT_DOMAIN: &[u8] = b"stwo.sn3-quotient-numerator.output.v1\0";
const INPUT_RECIPE_DOMAIN: &[u8] = b"stwo.sn3-quotient-numerator.input-recipe.v2\0";
const SOURCE_IDENTITY_DOMAIN: &[u8] = b"stwo.sn3-quotient-numerator.sources.v1\0";
const BOUNDARY_RUST_SOURCE_IDENTITY_DOMAIN: &[u8] =
    b"stwo.sn3-numerator-to-fri-input.rust-sources.v1\0";
const BOUNDARY_ARTIFACT_IDENTITY_DOMAIN: &[u8] =
    b"stwo.sn3-numerator-to-fri-input.artifact-identity.v1\0";
const NO_INDEX: u32 = u32::MAX;
const AFFINE_PATTERN_VERSION: u32 = 1;
const AFFINE_PATTERN_MODULUS: u64 = 2_147_483_646;
// Coprime to P - 1, so one affine stream cannot repeat before the full field cycle.
const AFFINE_PATTERN_ROW_MULTIPLIER: u64 = 1_000_003;
const SOURCE_PATTERN_SEED_BASE: u64 = 17;
const SOURCE_PATTERN_SEED_STRIDE: u64 = 104_729;
pub(super) const TWIDDLE_PATTERN_SEED: u64 = 15_485_863;

pub(super) struct ArtifactIdentity {
    pub(super) boundary_seal_blake3: Hash,
    pub(super) boundary_rust_source_blake3: Hash,
    pub(super) numerator_comparator_source_blake3: Hash,
    pub(super) ordinary_cuda_source_blake3: Hash,
    pub(super) test_binary_blake3: Hash,
    boundary_source_projection_sha256: Option<String>,
    boundary_cuda_module_sha256: Option<String>,
    pub(super) cuda_build_mode: &'static str,
    pub(super) expected_cuda_module_build_identity: Hash,
    pub(super) linked_cuda_module_build_identity: Hash,
    pub(super) cuda_module_target_sms: Vec<u32>,
}

impl ArtifactIdentity {
    pub(super) fn boundary_source_projection_json(&self) -> String {
        optional_hash_json(self.boundary_source_projection_sha256.as_deref())
    }

    pub(super) fn boundary_cuda_module_json(&self) -> String {
        optional_hash_json(self.boundary_cuda_module_sha256.as_deref())
    }

    pub(super) fn boundary_source_projection_sha256(&self) -> Option<&str> {
        self.boundary_source_projection_sha256.as_deref()
    }

    pub(super) fn boundary_cuda_module_sha256(&self) -> Option<&str> {
        self.boundary_cuda_module_sha256.as_deref()
    }

    pub(super) fn is_complete(&self) -> bool {
        self.boundary_source_projection_sha256.is_some()
            && self.boundary_cuda_module_sha256.is_some()
            && self.cuda_build_mode == "cuda"
            && self.ordinary_cuda_source_blake3.as_bytes() != &[0; 32]
            && self.expected_cuda_module_build_identity.as_bytes() != &[0; 32]
            && self.expected_cuda_module_build_identity == self.linked_cuda_module_build_identity
            && !self.cuda_module_target_sms.is_empty()
    }
}

pub(super) fn artifact_identity() -> ArtifactIdentity {
    let boundary_rust_source_blake3 = boundary_rust_source_digest();
    let numerator_comparator_source_blake3 = candidate_source_digest();
    let ordinary_cuda_source_blake3 =
        Hash::from_bytes(stwo_backend_cuda_kernels::static_cuda_source_identity());
    let test_binary_blake3 =
        file_blake3(std::env::current_exe().expect("current test binary path"));
    let boundary_source_projection_sha256 =
        optional_sha256("STWO_SN3_BOUNDARY_SOURCE_PROJECTION_SHA256");
    let boundary_cuda_module_sha256 = optional_sha256("STWO_SN3_BOUNDARY_CUDA_MODULE_SHA256");
    let expected_cuda_module_build_identity =
        Hash::from_bytes(stwo_backend_cuda_kernels::expected_static_cuda_module_build_identity());
    let linked_cuda_module_build_identity = Hash::from_bytes(
        stwo_backend_cuda_kernels::static_cuda_module_build_identity()
            .expect("read linked ordinary CUDA archive build-identity receipt"),
    );
    assert_eq!(
        linked_cuda_module_build_identity, expected_cuda_module_build_identity,
        "linked ordinary CUDA archive build-identity receipt drift"
    );
    let cuda_module_target_sms =
        stwo_backend_cuda_kernels::static_cuda_module_target_sms().to_vec();
    let cuda_build_mode = stwo_backend_cuda_kernels::BUILD_MODE;
    let boundary_seal_blake3 = boundary_artifact_digest(
        boundary_rust_source_blake3,
        ordinary_cuda_source_blake3,
        test_binary_blake3,
        boundary_source_projection_sha256.as_deref(),
        boundary_cuda_module_sha256.as_deref(),
        cuda_build_mode,
        expected_cuda_module_build_identity,
        linked_cuda_module_build_identity,
        &cuda_module_target_sms,
    );
    ArtifactIdentity {
        boundary_seal_blake3,
        boundary_rust_source_blake3,
        numerator_comparator_source_blake3,
        ordinary_cuda_source_blake3,
        test_binary_blake3,
        boundary_source_projection_sha256,
        boundary_cuda_module_sha256,
        cuda_build_mode,
        expected_cuda_module_build_identity,
        linked_cuda_module_build_identity,
        cuda_module_target_sms,
    }
}

pub(super) struct CanonicalOutput {
    words: Vec<u32>,
    digest: Hash,
}

impl CanonicalOutput {
    pub(super) fn len_bytes(&self) -> u64 {
        u64::try_from(self.words.len())
            .unwrap()
            .checked_mul(4)
            .unwrap()
    }

    pub(super) fn digest(&self) -> &Hash {
        &self.digest
    }
}

#[derive(Clone, Copy)]
struct OutputRange {
    slice: ArenaSlice,
    words: usize,
    kind: u32,
    group: u32,
    coordinate: u32,
}

pub(super) fn capture_canonical_output(
    fixture: &BenchmarkArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
) -> CanonicalOutput {
    let ranges = output_ranges(fixture, requirements);
    let total_words = ranges.iter().map(|range| range.words).sum();
    let mut words = Vec::with_capacity(total_words);
    let mut hasher = output_hasher(&ranges);
    for range in &ranges {
        hash_range_header(&mut hasher, range);
        for offset in (0..range.words).step_by(COPY_CHUNK_WORDS) {
            let chunk = read_chunk(fixture, *range, offset);
            hash_words_le(&mut hasher, &chunk);
            words.extend_from_slice(&chunk);
        }
    }
    assert_eq!(words.len(), total_words);
    CanonicalOutput {
        words,
        digest: hasher.finalize(),
    }
}

pub(super) fn assert_canonical_output(
    fixture: &BenchmarkArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    expected: &CanonicalOutput,
    label: &str,
) -> Hash {
    let ranges = output_ranges(fixture, requirements);
    let total_words: usize = ranges.iter().map(|range| range.words).sum();
    assert_eq!(
        expected.words.len(),
        total_words,
        "{label}: output shape drift"
    );
    let mut hasher = output_hasher(&ranges);
    let mut canonical_offset = 0usize;
    for range in &ranges {
        hash_range_header(&mut hasher, range);
        for range_offset in (0..range.words).step_by(COPY_CHUNK_WORDS) {
            let actual = read_chunk(fixture, *range, range_offset);
            let end = canonical_offset.checked_add(actual.len()).unwrap();
            let expected_chunk = &expected.words[canonical_offset..end];
            if let Some(index) = actual
                .iter()
                .zip(expected_chunk)
                .position(|(actual, expected)| actual != expected)
            {
                panic!(
                    "{label}: {} differs at canonical word {} (range word {}): expected {}, got {}",
                    range_name(*range),
                    canonical_offset + index,
                    range_offset + index,
                    expected_chunk[index],
                    actual[index],
                );
            }
            hash_words_le(&mut hasher, &actual);
            canonical_offset = end;
        }
    }
    assert_eq!(canonical_offset, total_words);
    let digest = hasher.finalize();
    assert_eq!(digest, expected.digest, "{label}: canonical digest drift");
    digest
}

pub(super) fn input_recipe_digest(
    topology: &[QuotientNumeratorColumnTopology],
    requirements: &QuotientNumeratorWorkspaceRequirements,
    hybrid: &QuotientNumeratorHybridPlan,
    points: &[CirclePoint<SecureField>],
) -> Hash {
    let mut recipe = RecipeHasher::new();
    recipe.u32(AFFINE_PATTERN_VERSION);
    recipe.u64(AFFINE_PATTERN_MODULUS);
    recipe.u64(AFFINE_PATTERN_ROW_MULTIPLIER);
    recipe.u64(SOURCE_PATTERN_SEED_BASE);
    recipe.u64(SOURCE_PATTERN_SEED_STRIDE);
    recipe.u64(TWIDDLE_PATTERN_SEED);
    recipe.u32(requirements.config.lifting_log_size);
    recipe.u32(requirements.config.log_blowup_factor);
    recipe.usize(requirements.config.max_lde_tile_words);

    recipe.usize(topology.len());
    for (index, column) in topology.iter().enumerate() {
        recipe.u32(column.coefficient_log_size);
        recipe.u32(match column.source_kind {
            QuotientNumeratorSourceKind::Evaluation => 0,
            QuotientNumeratorSourceKind::Coefficients => 1,
        });
        recipe.usize(column.samples.len());
        for sample in &column.samples {
            recipe.u32(sample.input_index);
            recipe.point(sample.shape_point);
        }
        recipe.usize(source_words(column));
        recipe.u64(source_pattern_seed(index));
    }

    recipe.words(&point_words(points));
    recipe.words(&secure_words(&oods_values(points.len())));
    recipe.words(&secure_words(&[random_coefficient()]));
    recipe.usize(requirements.forward_twiddle_words);
    recipe.u64(TWIDDLE_PATTERN_SEED);

    recipe.usize(requirements.input_sample_count);
    recipe.usize(requirements.term_count);
    recipe.usize(requirements.groups.len());
    for group in &requirements.groups {
        recipe.point(group.shape_point);
        recipe.u32(group.log_size);
        recipe.usize(group.value_words);
        recipe.usize(group.coefficient_source_count);
    }
    recipe.usize(requirements.batches.len());
    for batch in &requirements.batches {
        recipe.u32(batch.evaluation_log_size);
        recipe.usize(batch.source_count);
        recipe.usize(batch.coefficient_count);
        recipe.usize(batch.term_count);
        recipe.usize(batch.lde_words);
    }
    for words in [
        requirements.runtime_term_words,
        requirements.group_term_index_words,
        requirements.group_offset_words,
        requirements.line_coefficient_words,
        requirements.term_point_words,
        requirements.batch_term_words,
        requirements.batch_group_offset_words,
        requirements.batch_source_pointer_words,
        requirements.coefficient_pointer_words,
        requirements.coefficient_size_words,
        requirements.coefficient_output_pointer_words,
        requirements.output_pointer_words,
        requirements.output_log_size_words,
        requirements.lde_tile_words,
        requirements.forward_twiddle_words,
        requirements.max_output_size,
    ] {
        recipe.usize(words);
    }

    recipe.usizes(hybrid.schedule_groups());
    recipe.usizes(hybrid.source_columns());
    recipe.words(hybrid.packed_terms());
    recipe.words(hybrid.packed_group_offsets());
    recipe.usize(hybrid.batches().len());
    for batch in hybrid.batches() {
        recipe.usize(batch.term_offset);
        recipe.usize(batch.term_count);
        recipe.usize(batch.group_offset);
    }
    let report = hybrid.report();
    for value in [
        report.group_count,
        report.eligible_group_count,
        report.legacy_group_count,
        report.legacy_batch_count,
        report.eligible_output_rows,
        report.legacy_output_rows,
    ] {
        recipe.usize(value);
    }
    recipe.u64(report.legacy_logical_output_bytes);
    recipe.u64(report.hybrid_logical_output_bytes);
    recipe.finish()
}

pub(super) fn source_pattern_seed(index: usize) -> u64 {
    (SOURCE_PATTERN_SEED_BASE + u64::try_from(index).unwrap() * SOURCE_PATTERN_SEED_STRIDE)
        % AFFINE_PATTERN_MODULUS
}

pub(super) fn assert_affine_pattern_sanity() {
    let source_zero = source_pattern_seed(0);
    let values = [
        affine_pattern_word(source_zero, 0),
        affine_pattern_word(source_zero, 1),
        affine_pattern_word(source_pattern_seed(1), 0),
        affine_pattern_word(TWIDDLE_PATTERN_SEED, 0),
    ];
    assert!(values
        .iter()
        .all(|&value| value != 0 && value < 0x7fff_ffff));
    assert_ne!(values[0], values[1], "row pattern must vary by row");
    assert_ne!(values[0], values[2], "source pattern must vary by column");
    assert_ne!(
        values[0], values[3],
        "twiddle and source domains must differ"
    );
}

pub(super) fn upload_affine_pattern(
    arena: &DeviceArena,
    slot: ArenaSlotId,
    words: usize,
    seed: u64,
) {
    let slice = arena.bind(slot).unwrap();
    assert_eq!(slice.len_words(), words, "affine pattern shape drift");
    let mut host = vec![0u32; words.min(PATTERN_CHUNK_WORDS)];
    for offset in (0..words).step_by(PATTERN_CHUNK_WORDS) {
        let count = PATTERN_CHUNK_WORDS.min(words - offset);
        fill_affine_pattern(&mut host[..count], seed, offset);
        unsafe {
            arena
                .context()
                .memcpy_h2d_async(
                    slice.as_u32_ptr().add(offset).cast(),
                    host.as_ptr().cast(),
                    count * 4,
                )
                .unwrap();
        }
        // The bounded host chunk is reused, so its asynchronous copy must finish first.
        arena.context().sync().unwrap();
    }
}

pub(super) fn poison_outputs(
    fixture: &BenchmarkArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    poison: u32,
) {
    for range in output_ranges(fixture, requirements) {
        unsafe {
            fixture
                .arena
                .context()
                .fill_u32_async(range.slice.as_u32_ptr(), poison, range.words)
                .unwrap();
        }
    }
    fixture.arena.context().sync().unwrap();
}

fn affine_pattern_word(seed: u64, row: usize) -> u32 {
    let row = u64::try_from(row).unwrap() % AFFINE_PATTERN_MODULUS;
    let state = (seed + row * AFFINE_PATTERN_ROW_MULTIPLIER) % AFFINE_PATTERN_MODULUS;
    u32::try_from(state + 1).unwrap()
}

fn fill_affine_pattern(output: &mut [u32], seed: u64, row_offset: usize) {
    let row = u64::try_from(row_offset).unwrap() % AFFINE_PATTERN_MODULUS;
    let mut state = (seed + row * AFFINE_PATTERN_ROW_MULTIPLIER) % AFFINE_PATTERN_MODULUS;
    for word in output {
        *word = u32::try_from(state + 1).unwrap();
        state += AFFINE_PATTERN_ROW_MULTIPLIER;
        if state >= AFFINE_PATTERN_MODULUS {
            state -= AFFINE_PATTERN_MODULUS;
        }
    }
}

pub(super) fn percentile(samples: &[f64], percentage: usize) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = (percentage * sorted.len()).div_ceil(100).saturating_sub(1);
    sorted[rank]
}

pub(super) fn json_samples(samples: &[f64]) -> String {
    format!(
        "[{}]",
        samples
            .iter()
            .map(|sample| format!("{sample:.6}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn output_ranges(
    fixture: &BenchmarkArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
) -> Vec<OutputRange> {
    let mut ranges = Vec::with_capacity(2 + 4 * requirements.groups.len());
    ranges.push(OutputRange {
        slice: fixture.arena.bind(SAMPLE_POINTS_OUTPUT).unwrap(),
        words: requirements.groups.len() * 8,
        kind: 0,
        group: NO_INDEX,
        coordinate: NO_INDEX,
    });
    ranges.push(OutputRange {
        slice: fixture.arena.bind(FIRST_TERMS_OUTPUT).unwrap(),
        words: requirements.groups.len() * 4,
        kind: 1,
        group: NO_INDEX,
        coordinate: NO_INDEX,
    });
    for (group, requirement) in requirements.groups.iter().enumerate() {
        for coordinate in 0..4 {
            ranges.push(OutputRange {
                slice: fixture
                    .arena
                    .bind(fixture.destination_ids[group][coordinate])
                    .unwrap(),
                words: requirement.value_words,
                kind: 2,
                group: u32::try_from(group).unwrap(),
                coordinate: u32::try_from(coordinate).unwrap(),
            });
        }
    }
    ranges
}

fn output_hasher(ranges: &[OutputRange]) -> Hasher {
    let mut hasher = Hasher::new();
    hasher.update(OUTPUT_DOMAIN);
    hasher.update(&u64::try_from(ranges.len()).unwrap().to_le_bytes());
    hasher
}

fn hash_range_header(hasher: &mut Hasher, range: &OutputRange) {
    hasher.update(&range.kind.to_le_bytes());
    hasher.update(&range.group.to_le_bytes());
    hasher.update(&range.coordinate.to_le_bytes());
    hasher.update(&u64::try_from(range.words).unwrap().to_le_bytes());
}

fn read_chunk(fixture: &BenchmarkArena, range: OutputRange, offset: usize) -> Vec<u32> {
    let count = COPY_CHUNK_WORDS.min(range.words - offset);
    let mut host = vec![0u32; count];
    unsafe {
        fixture
            .arena
            .context()
            .memcpy_d2h_async(
                host.as_mut_ptr().cast(),
                range.slice.as_u32_ptr().add(offset).cast(),
                count * 4,
            )
            .unwrap();
    }
    fixture.arena.context().sync().unwrap();
    host
}

fn range_name(range: OutputRange) -> String {
    match range.kind {
        0 => "sample points".to_owned(),
        1 => "first terms".to_owned(),
        2 => format!("group {} coordinate {}", range.group, range.coordinate),
        _ => unreachable!(),
    }
}

fn boundary_rust_source_digest() -> Hash {
    let sources: &[(&str, &[u8])] = &[
        (
            "tests/prepared_quotient_numerator_sn3_bench_native.rs",
            include_bytes!("../prepared_quotient_numerator_sn3_bench_native.rs").as_slice(),
        ),
        (
            "tests/support/sn3_quotient_numerator_bench.rs",
            include_bytes!("sn3_quotient_numerator_bench.rs").as_slice(),
        ),
        (
            "tests/support/sn3_quotient_run_sum_ab.rs",
            include_bytes!("sn3_quotient_run_sum_ab.rs").as_slice(),
        ),
        (
            "tests/support/sn3_quotient_topology_fixture.rs",
            include_bytes!("sn3_quotient_topology_fixture.rs").as_slice(),
        ),
        (
            "src/backend/quotient_numerator_single_write.rs",
            include_bytes!("../../src/backend/quotient_numerator_single_write.rs").as_slice(),
        ),
        (
            "src/backend/quotient_numerator_staged_single_write.rs",
            include_bytes!("../../src/backend/quotient_numerator_staged_single_write.rs")
                .as_slice(),
        ),
        (
            "src/backend/quotient_numerator_run_sum.rs",
            include_bytes!("../../src/backend/quotient_numerator_run_sum.rs").as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator.rs").as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator/plan.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/plan.rs").as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator/bindings.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/bindings.rs").as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator/launch.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/launch.rs").as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator/single_write.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/single_write.rs")
                .as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator/run_sum.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/run_sum.rs").as_slice(),
        ),
        (
            "src/backend/prepared_quotient.rs",
            include_bytes!("../../src/backend/prepared_quotient.rs").as_slice(),
        ),
        (
            "src/backend/prepared_interpolation.rs",
            include_bytes!("../../src/backend/prepared_interpolation.rs").as_slice(),
        ),
        (
            "src/backend/prepared_interpolation/authority.rs",
            include_bytes!("../../src/backend/prepared_interpolation/authority.rs").as_slice(),
        ),
        (
            "src/backend/quotient_producer_b2n.rs",
            include_bytes!("../../src/backend/quotient_producer_b2n.rs").as_slice(),
        ),
        (
            "src/backend/exec_context.rs",
            include_bytes!("../../src/backend/exec_context.rs").as_slice(),
        ),
        (
            "src/columns/bindings.rs",
            include_bytes!("../../src/columns/bindings.rs").as_slice(),
        ),
        (
            "backend-cuda-kernels/src/lib.rs",
            include_bytes!("../../../backend-cuda-kernels/src/lib.rs").as_slice(),
        ),
        (
            "backend-cuda-kernels/src/raw.rs",
            include_bytes!("../../../backend-cuda-kernels/src/raw.rs").as_slice(),
        ),
        (
            "backend-cuda-kernels/build.rs",
            include_bytes!("../../../backend-cuda-kernels/build.rs").as_slice(),
        ),
    ];
    source_set_digest(BOUNDARY_RUST_SOURCE_IDENTITY_DOMAIN, sources)
}

fn candidate_source_digest() -> Hash {
    let sources: &[(&str, &[u8])] = &[
        (
            "tests/prepared_quotient_numerator_sn3_bench_native.rs",
            include_bytes!("../prepared_quotient_numerator_sn3_bench_native.rs").as_slice(),
        ),
        (
            "tests/support/sn3_quotient_numerator_bench.rs",
            include_bytes!("sn3_quotient_numerator_bench.rs").as_slice(),
        ),
        (
            "tests/support/sn3_quotient_run_sum_ab.rs",
            include_bytes!("sn3_quotient_run_sum_ab.rs").as_slice(),
        ),
        (
            "tests/support/sn3_quotient_topology_fixture.rs",
            include_bytes!("sn3_quotient_topology_fixture.rs").as_slice(),
        ),
        (
            "src/backend/quotient_numerator_single_write.rs",
            include_bytes!("../../src/backend/quotient_numerator_single_write.rs").as_slice(),
        ),
        (
            "src/backend/quotient_numerator_run_sum.rs",
            include_bytes!("../../src/backend/quotient_numerator_run_sum.rs").as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator.rs").as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator/plan.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/plan.rs").as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator/bindings.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/bindings.rs").as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator/launch.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/launch.rs").as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator/single_write.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/single_write.rs")
                .as_slice(),
        ),
        (
            "src/backend/prepared_quotient_numerator/run_sum.rs",
            include_bytes!("../../src/backend/prepared_quotient_numerator/run_sum.rs").as_slice(),
        ),
        (
            "cuda/quotient_numerator_native_run_sum.cu",
            include_bytes!(
                "../../../backend-cuda-kernels/cuda/quotient_numerator_native_run_sum.cu"
            )
            .as_slice(),
        ),
        (
            "cuda/quotient_numerator_single_write.cu",
            include_bytes!("../../../backend-cuda-kernels/cuda/quotient_numerator_single_write.cu")
                .as_slice(),
        ),
        (
            "cuda/quotient_numerator_single_write.cuh",
            include_bytes!(
                "../../../backend-cuda-kernels/cuda/quotient_numerator_single_write.cuh"
            )
            .as_slice(),
        ),
        (
            "cuda/quotients.cu",
            include_bytes!("../../../backend-cuda-kernels/cuda/quotients.cu").as_slice(),
        ),
        (
            "cuda/quotients.cuh",
            include_bytes!("../../../backend-cuda-kernels/cuda/quotients.cuh").as_slice(),
        ),
    ];
    source_set_digest(SOURCE_IDENTITY_DOMAIN, sources)
}

fn source_set_digest(domain: &[u8], sources: &[(&str, &[u8])]) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(domain);
    hasher.update(&u64::try_from(sources.len()).unwrap().to_le_bytes());
    for (name, bytes) in sources {
        hasher.update(&u64::try_from(name.len()).unwrap().to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(&u64::try_from(bytes.len()).unwrap().to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finalize()
}

#[allow(clippy::too_many_arguments)]
fn boundary_artifact_digest(
    boundary_rust_source_blake3: Hash,
    ordinary_cuda_source_blake3: Hash,
    test_binary_blake3: Hash,
    boundary_source_projection_sha256: Option<&str>,
    boundary_cuda_module_sha256: Option<&str>,
    cuda_build_mode: &str,
    expected_cuda_module_build_identity: Hash,
    linked_cuda_module_build_identity: Hash,
    cuda_module_target_sms: &[u32],
) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(BOUNDARY_ARTIFACT_IDENTITY_DOMAIN);
    for digest in [
        boundary_rust_source_blake3,
        ordinary_cuda_source_blake3,
        test_binary_blake3,
        expected_cuda_module_build_identity,
        linked_cuda_module_build_identity,
    ] {
        hasher.update(digest.as_bytes());
    }
    hash_optional_text(&mut hasher, boundary_source_projection_sha256);
    hash_optional_text(&mut hasher, boundary_cuda_module_sha256);
    hasher.update(&u64::try_from(cuda_build_mode.len()).unwrap().to_le_bytes());
    hasher.update(cuda_build_mode.as_bytes());
    hasher.update(
        &u64::try_from(cuda_module_target_sms.len())
            .unwrap()
            .to_le_bytes(),
    );
    for sm in cuda_module_target_sms {
        hasher.update(&sm.to_le_bytes());
    }
    hasher.finalize()
}

fn hash_optional_text(hasher: &mut Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hasher.update(&u64::try_from(value.len()).unwrap().to_le_bytes());
            hasher.update(value.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn file_blake3(path: impl AsRef<std::path::Path>) -> Hash {
    let path = path.as_ref();
    let mut file = File::open(path)
        .unwrap_or_else(|error| panic!("open test binary {}: {error}", path.display()));
    let mut hasher = Hasher::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("read test binary {}: {error}", path.display()));
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    hasher.finalize()
}

fn optional_sha256(name: &str) -> Option<String> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return None,
        Err(std::env::VarError::NotUnicode(_)) => panic!("{name} must be UTF-8"),
    };
    assert!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{name} must be 64 lowercase hexadecimal characters"
    );
    Some(value)
}

fn optional_hash_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{value}\""))
        .unwrap_or_else(|| "null".to_owned())
}

#[cfg(target_endian = "little")]
fn hash_words_le(hasher: &mut Hasher, words: &[u32]) {
    // SAFETY: every `u32` is initialized, and a byte slice may view any initialized object.
    let bytes = unsafe {
        std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), std::mem::size_of_val(words))
    };
    hasher.update(bytes);
}

#[cfg(target_endian = "big")]
fn hash_words_le(hasher: &mut Hasher, words: &[u32]) {
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
}

struct RecipeHasher(Hasher);

impl RecipeHasher {
    fn new() -> Self {
        let mut hasher = Hasher::new();
        hasher.update(INPUT_RECIPE_DOMAIN);
        Self(hasher)
    }

    fn u32(&mut self, value: u32) {
        self.0.update(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(&value.to_le_bytes());
    }

    fn usize(&mut self, value: usize) {
        self.u64(u64::try_from(value).unwrap());
    }

    fn words(&mut self, words: &[u32]) {
        self.usize(words.len());
        hash_words_le(&mut self.0, words);
    }

    fn usizes(&mut self, values: &[usize]) {
        self.usize(values.len());
        for &value in values {
            self.usize(value);
        }
    }

    fn point(&mut self, point: CirclePoint<SecureField>) {
        self.words(&point_words(&[point]));
    }

    fn finish(self) -> Hash {
        self.0.finalize()
    }
}
