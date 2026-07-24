//! Exact retained FixedImage topology and arena lifetime used by the SN3 A/B.
//!
//! This is the `3a97d092` topology factored out of the retired diagnostic:
//! one coefficient oracle materializes 152 persistent evaluation aliases,
//! then its descriptor workspace is reused by one retained prepared object.

use blake3::{Hash, Hasher};

use super::sn3_quotient_numerator_bench::{
    input_recipe_digest, poison_outputs, source_pattern_seed, upload_affine_pattern,
    TWIDDLE_PATTERN_SEED,
};
use super::sn3_quotient_topology_fixture::load_sn3_topology_fixture;
use super::*;

pub(crate) struct BenchmarkArena {
    pub(crate) arena: DeviceArena,
    pub(crate) oracle_slots: QuotientNumeratorWorkspaceSlots,
    pub(crate) retained_slots: QuotientNumeratorWorkspaceSlots,
    pub(crate) quotient_slots: QuotientWorkspaceSlots,
    pub(crate) source_ids: Vec<ArenaSlotId>,
    pub(crate) retained_source_ids: Vec<ArenaSlotId>,
    pub(crate) destination_ids: Vec<[ArenaSlotId; 4]>,
    pub(crate) retained_manifest_blake3: Hash,
    pub(crate) allocation_bytes: u64,
}

struct BenchmarkArenaPlan {
    layout: ArenaLayout,
    oracle_slots: QuotientNumeratorWorkspaceSlots,
    retained_slots: QuotientNumeratorWorkspaceSlots,
    quotient_slots: QuotientWorkspaceSlots,
    source_ids: Vec<ArenaSlotId>,
    retained_source_ids: Vec<ArenaSlotId>,
    destination_ids: Vec<[ArenaSlotId; 4]>,
    retained_manifest_blake3: Hash,
    allocation_bytes: u64,
}

pub(crate) struct RetainedShape {
    pub(crate) control_requirements: QuotientNumeratorWorkspaceRequirements,
    pub(crate) control_plan: QuotientNumeratorStagedSingleWritePlan,
    pub(crate) retained_topology: Vec<QuotientNumeratorColumnTopology>,
    pub(crate) retained_requirements: QuotientNumeratorWorkspaceRequirements,
    pub(crate) retained_plan: QuotientNumeratorStagedSingleWritePlan,
    pub(crate) quotient_requirements: QuotientWorkspaceRequirements,
}

impl BenchmarkArena {
    pub(crate) fn new(topology: &[QuotientNumeratorColumnTopology], shape: &RetainedShape) -> Self {
        let plan = benchmark_arena_plan(topology, shape);
        let arena = DeviceArena::new(CudaExecContext::new().unwrap(), plan.layout).unwrap();
        Self {
            arena,
            oracle_slots: plan.oracle_slots,
            retained_slots: plan.retained_slots,
            quotient_slots: plan.quotient_slots,
            source_ids: plan.source_ids,
            retained_source_ids: plan.retained_source_ids,
            destination_ids: plan.destination_ids,
            retained_manifest_blake3: plan.retained_manifest_blake3,
            allocation_bytes: plan.allocation_bytes,
        }
    }

    pub(crate) fn columns(
        &self,
        topology: &[QuotientNumeratorColumnTopology],
        source_ids: &[ArenaSlotId],
    ) -> Vec<QuotientNumeratorColumn> {
        assert_eq!(topology.len(), source_ids.len());
        topology
            .iter()
            .zip(source_ids)
            .map(|(topology, &id)| QuotientNumeratorColumn {
                coefficient_log_size: topology.coefficient_log_size,
                source: match topology.source_kind {
                    QuotientNumeratorSourceKind::Evaluation => {
                        QuotientNumeratorColumnSource::Evaluation(self.arena.bind(id).unwrap())
                    }
                    QuotientNumeratorSourceKind::Coefficients => {
                        QuotientNumeratorColumnSource::Coefficients(self.arena.bind(id).unwrap())
                    }
                },
                samples: topology.samples.clone(),
            })
            .collect()
    }

    pub(crate) fn destinations(
        &self,
        requirements: &QuotientNumeratorWorkspaceRequirements,
    ) -> Vec<QuotientNumeratorDestination> {
        requirements
            .groups
            .iter()
            .zip(&self.destination_ids)
            .map(|(group, ids)| QuotientNumeratorDestination {
                log_size: group.log_size,
                coordinates: ids.map(|id| self.arena.bind(id).unwrap()),
            })
            .collect()
    }
}

pub(crate) fn exact_shape(topology: &[QuotientNumeratorColumnTopology]) -> RetainedShape {
    let config = retained_config();
    let control_requirements = quotient_numerator_workspace_requirements(config, topology).unwrap();
    let control_plan = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
        config,
        topology,
        &[STAGED_OVERFLOW_WORDS],
    )
    .unwrap();
    assert_control_shape(&control_requirements, &control_plan);
    let retained_topology = retained_topology(topology, &control_plan);
    let retained_requirements =
        quotient_numerator_workspace_requirements(config, &retained_topology).unwrap();
    let retained_plan = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
        config,
        &retained_topology,
        &[],
    )
    .unwrap();
    assert_retained_shape(&retained_requirements, &retained_plan);
    let quotient_requirements =
        quotient_workspace_requirements(SN3_QUOTIENT_CONFIG, &GROUP_LOGS).unwrap();
    assert_eq!(quotient_requirements.output_value_words, 67_108_864);
    RetainedShape {
        control_requirements,
        control_plan,
        retained_topology,
        retained_requirements,
        retained_plan,
        quotient_requirements,
    }
}

pub(crate) fn assert_host_shape() {
    let sn3 = load_sn3_topology_fixture(EXPECTED_SN3_TOPOLOGY_FIXTURE_BLAKE3);
    assert_eq!(sn3.config, EXPECTED_SN3_TOPOLOGY_CONFIG);
    assert_eq!(sn3.topology.len(), 5_886);
    assert_eq!(
        sn3.topology
            .iter()
            .filter(|column| column.source_kind == QuotientNumeratorSourceKind::Coefficients)
            .count(),
        161
    );
    assert_eq!(sn3.requirements.term_count, 6_341);
    assert_eq!(
        input_recipe_digest(
            &sn3.topology,
            &sn3.requirements,
            &sn3.hybrid,
            &sn3.input_points,
        )
        .to_hex()
        .as_str(),
        EXPECTED_SN3_INPUT_RECIPE_BLAKE3
    );
    let shape = exact_shape(&sn3.topology);
    let plan = benchmark_arena_plan(&sn3.topology, &shape);
    assert_eq!(plan.allocation_bytes, EXPECTED_SN3_ARENA_BYTES);
    assert_eq!(
        plan.retained_manifest_blake3.to_hex().as_str(),
        EXPECTED_RETAINED_MANIFEST_BLAKE3
    );
    assert_reused_workspace_shape(&plan, &shape.control_plan);
}

fn retained_config() -> QuotientNumeratorWorkspaceConfig {
    QuotientNumeratorWorkspaceConfig {
        max_lde_tile_words: 32 * (1usize << EXPECTED_SN3_TOPOLOGY_CONFIG.lifting_log_size),
        ..EXPECTED_SN3_TOPOLOGY_CONFIG
    }
}

fn retained_topology(
    control: &[QuotientNumeratorColumnTopology],
    staged: &QuotientNumeratorStagedSingleWritePlan,
) -> Vec<QuotientNumeratorColumnTopology> {
    let mut retained = control.to_vec();
    assert_eq!(staged.coefficient_ldes().len(), RETAINED_COLUMN_COUNT);
    for lde in staged.coefficient_ldes() {
        let column = &mut retained[lde.column()];
        assert_eq!(
            column.source_kind,
            QuotientNumeratorSourceKind::Coefficients
        );
        assert!(!column.samples.is_empty());
        assert_eq!(lde.evaluation_log_size(), column.coefficient_log_size + 1);
        column.source_kind = QuotientNumeratorSourceKind::Evaluation;
    }
    assert!(retained.iter().all(|column| {
        column.source_kind == QuotientNumeratorSourceKind::Evaluation || column.samples.is_empty()
    }));
    retained
}

fn assert_control_shape(
    requirements: &QuotientNumeratorWorkspaceRequirements,
    staged: &QuotientNumeratorStagedSingleWritePlan,
) {
    assert_eq!(requirements.config.max_lde_tile_words, STAGED_PRIMARY_WORDS);
    assert_eq!(requirements.batches.len(), 19);
    assert_eq!(requirements.term_count, 6_341);
    assert_eq!(staged.requirements(), requirements);
    assert_eq!(staged.packed_output_rows(), 25_165_264);
    assert_eq!(staged.coefficient_ldes().len(), RETAINED_COLUMN_COUNT);
    assert_eq!(staged.overflow_role_words(), [STAGED_OVERFLOW_WORDS]);
    assert_eq!(staged.report().primary_staging_words, 526_981_024);
    assert_eq!(
        staged.report().overflow_staging_words,
        STAGED_OVERFLOW_WORDS
    );
}

fn assert_retained_shape(
    requirements: &QuotientNumeratorWorkspaceRequirements,
    staged: &QuotientNumeratorStagedSingleWritePlan,
) {
    assert_eq!(requirements.config.max_lde_tile_words, STAGED_PRIMARY_WORDS);
    assert_eq!(requirements.batches.len(), 18);
    assert_eq!(requirements.term_count, 6_341);
    assert_eq!(
        requirements
            .groups
            .iter()
            .map(|group| group.log_size)
            .collect::<Vec<_>>(),
        GROUP_LOGS
    );
    assert_eq!(requirements.groups[0].coefficient_source_count, 0);
    assert_eq!(requirements.lde_tile_words, 0);
    assert_eq!(requirements.forward_twiddle_words, 0);
    assert_eq!(staged.requirements(), requirements);
    assert_eq!(staged.packed_output_rows(), 25_165_264);
    assert!(staged.coefficient_ldes().is_empty());
    assert!(staged.overflow_role_words().is_empty());
    assert_eq!(staged.report().coefficient_source_count, 0);
    assert_eq!(staged.report().factor32_batch_count, 18);
    assert_eq!(staged.report().total_staging_words, 0);
    assert_eq!(
        requirements
            .batches
            .iter()
            .map(|batch| batch.evaluation_log_size)
            .collect::<Vec<_>>(),
        [5, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]
    );
    assert_eq!(staged_lde_kernel_nodes(requirements), 0);
}

pub(crate) fn staged_lde_kernel_nodes(
    requirements: &QuotientNumeratorWorkspaceRequirements,
) -> u64 {
    requirements
        .batches
        .iter()
        .filter(|batch| batch.coefficient_count != 0)
        .map(|batch| {
            u64::try_from(batch.coefficient_count.div_ceil(65_535)).unwrap()
                * lde_n2b_kernel_nodes(batch.evaluation_log_size)
        })
        .sum()
}

fn lde_n2b_kernel_nodes(log_size: u32) -> u64 {
    1 + match log_size {
        3..=12 => u64::from(log_size),
        13..=19 => 2,
        20..=27 => 3,
        28..=30 => 4,
        _ => panic!("unsupported exact LDE log size {log_size}"),
    }
}

fn benchmark_arena_plan(
    topology: &[QuotientNumeratorColumnTopology],
    shape: &RetainedShape,
) -> BenchmarkArenaPlan {
    let requirements = &shape.control_requirements;
    let oracle_slots = workspace_slots(requirements, ORACLE_WORKSPACE_BASE, SHARED_STAGED_PRIMARY);
    let reserved_control_slots = workspace_slots(
        requirements,
        RESERVED_CONTROL_WORKSPACE_BASE,
        SHARED_STAGED_PRIMARY,
    );
    let retained_slots = workspace_slots(
        &shape.retained_requirements,
        ORACLE_WORKSPACE_BASE,
        SHARED_STAGED_PRIMARY,
    );
    let quotient_slots = quotient_workspace_slots();
    let mut specs = Vec::new();
    let mut cursor = 0usize;
    for slots in [&oracle_slots, &reserved_control_slots] {
        let start = cursor;
        for requirement in requirements.arena_slot_requirements(slots).unwrap() {
            if requirement.id != SHARED_STAGED_PRIMARY {
                push_spec(
                    &mut specs,
                    &mut cursor,
                    requirement.id,
                    requirement.len_words,
                    requirement.alignment_words,
                );
            }
        }
        assert_eq!(
            (cursor - start) as u64 * 4,
            STAGED_DESCRIPTOR_WORKSPACE_BYTES
        );
    }
    push_spec(
        &mut specs,
        &mut cursor,
        SHARED_STAGED_PRIMARY,
        STAGED_PRIMARY_WORDS,
        8,
    );
    push_spec(
        &mut specs,
        &mut cursor,
        SHARED_STAGED_OVERFLOW,
        STAGED_OVERFLOW_WORDS,
        8,
    );
    for (id, words) in [
        (OODS_POINTS, requirements.input_sample_count * 8),
        (OODS_VALUES, requirements.input_sample_count * 4),
        (RANDOM_COEFFICIENT, 4),
        (SAMPLE_POINTS_OUTPUT, requirements.groups.len() * 8),
        (FIRST_TERMS_OUTPUT, requirements.groups.len() * 4),
        (TWIDDLES, requirements.forward_twiddle_words),
    ] {
        push_spec(&mut specs, &mut cursor, id, words, 8);
    }
    let source_ids = topology
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let id = ArenaSlotId(SOURCE_BASE + u32::try_from(index).unwrap());
            push_spec(&mut specs, &mut cursor, id, source_words(column), 8);
            id
        })
        .collect::<Vec<_>>();
    let destination_ids = requirements
        .groups
        .iter()
        .enumerate()
        .map(|(group, requirement)| {
            std::array::from_fn(|coordinate| {
                let id = output_id(group, coordinate);
                push_spec(&mut specs, &mut cursor, id, requirement.value_words, 8);
                id
            })
        })
        .collect::<Vec<_>>();
    let quotient_start = cursor;
    for requirement in shape
        .quotient_requirements
        .arena_slot_requirements(&quotient_slots)
        .unwrap()
    {
        if requirement.id != SAMPLE_POINTS_OUTPUT && requirement.id != FIRST_TERMS_OUTPUT {
            push_spec(
                &mut specs,
                &mut cursor,
                requirement.id,
                requirement.len_words,
                requirement.alignment_words,
            );
        }
    }
    push_spec(
        &mut specs,
        &mut cursor,
        INVERSE_TWIDDLES,
        shape.quotient_requirements.inverse_twiddle_words,
        1,
    );
    assert_eq!(cursor - quotient_start, QUOTIENT_INCREMENTAL_ARENA_WORDS);
    let allocation_bytes = u64::try_from(cursor).unwrap().checked_mul(4).unwrap();

    assert_workspace_capacity(&shape.retained_requirements, &retained_slots, &specs);
    let primary = slot_spec(&specs, SHARED_STAGED_PRIMARY);
    let overflow = slot_spec(&specs, SHARED_STAGED_OVERFLOW);
    let mut ranges = specs
        .iter()
        .copied()
        .map(|slot| ArenaRangeSpec {
            live_mask: if matches!(slot.id, SHARED_STAGED_PRIMARY | SHARED_STAGED_OVERFLOW) {
                ORACLE_LIVE
            } else {
                BOTH_LIVE
            },
            slot,
        })
        .collect::<Vec<_>>();
    let mut retained_source_ids = source_ids.clone();
    let mut retained_image_words = 0usize;
    let mut primary_columns = 0usize;
    let mut overflow_columns = 0usize;
    for lde in shape.control_plan.coefficient_ldes() {
        let role_base = match lde.staging_role() {
            QuotientNumeratorStagingRole::Primary => {
                primary_columns += 1;
                primary.offset_words
            }
            QuotientNumeratorStagingRole::Overflow(0) => {
                overflow_columns += 1;
                overflow.offset_words
            }
            role => panic!("unexpected retained FixedImage role {role:?}"),
        };
        retained_image_words += lde.len_words();
        let id = retained_image_id(lde.column());
        retained_source_ids[lde.column()] = id;
        ranges.push(ArenaRangeSpec {
            slot: ArenaSlotSpec {
                id,
                offset_words: role_base + lde.role_offset_words(),
                len_words: lde.len_words(),
                alignment_words: 8,
            },
            live_mask: RETAINED_LIVE,
        });
    }
    assert_eq!((primary_columns, overflow_columns), (125, 27));
    assert_eq!(retained_image_words, RETAINED_IMAGE_WORDS);
    let layout = unsafe {
        // SAFETY: the coefficient oracle is dropped and synchronized before
        // the retained object is prepared. Their live masks never overlap.
        ArenaLayout::new_reused(cursor, &ranges)
    }
    .unwrap();
    let retained_manifest_blake3 = retained_manifest_digest(&layout, &shape.control_plan);
    BenchmarkArenaPlan {
        layout,
        oracle_slots,
        retained_slots,
        quotient_slots,
        source_ids,
        retained_source_ids,
        destination_ids,
        retained_manifest_blake3,
        allocation_bytes,
    }
}

fn workspace_slots(
    requirements: &QuotientNumeratorWorkspaceRequirements,
    base: u32,
    lde_tile: ArenaSlotId,
) -> QuotientNumeratorWorkspaceSlots {
    let id = |offset| ArenaSlotId(base + offset);
    QuotientNumeratorWorkspaceSlots {
        runtime_terms: id(0),
        group_term_indices: id(1),
        group_offsets: id(2),
        line_coefficients: id(3),
        term_points: id(4),
        batch_terms: id(5),
        batch_group_offsets: id(6),
        batch_source_ptrs: id(7),
        output_ptrs: id(8),
        output_log_sizes: id(9),
        coefficient_ptrs: (requirements.coefficient_pointer_words != 0).then_some(id(10)),
        coefficient_sizes: (requirements.coefficient_size_words != 0).then_some(id(11)),
        coefficient_output_ptrs: (requirements.coefficient_output_pointer_words != 0)
            .then_some(id(12)),
        lde_tile: (requirements.lde_tile_words != 0).then_some(lde_tile),
    }
}

fn quotient_workspace_slots() -> QuotientWorkspaceSlots {
    let id = |offset| ArenaSlotId(QUOTIENT_WORKSPACE_BASE + offset);
    QuotientWorkspaceSlots {
        sample_points: SAMPLE_POINTS_OUTPUT,
        first_linear_terms: FIRST_TERMS_OUTPUT,
        partial_log_sizes: id(0),
        partial_coordinate_ptrs: id(1),
        subdomain_coordinate_ptrs: id(2),
        output_coordinate_ptrs: id(3),
        coefficient_sizes: id(4),
        subdomain_values: id(5),
        output_values: id(6),
    }
}

fn assert_workspace_capacity(
    requirements: &QuotientNumeratorWorkspaceRequirements,
    slots: &QuotientNumeratorWorkspaceSlots,
    specs: &[ArenaSlotSpec],
) {
    for requirement in requirements.arena_slot_requirements(slots).unwrap() {
        let allocated = slot_spec(specs, requirement.id);
        assert!(allocated.len_words >= requirement.len_words);
        assert_eq!(allocated.offset_words % requirement.alignment_words, 0);
    }
}

fn assert_reused_workspace_shape(
    plan: &BenchmarkArenaPlan,
    staged: &QuotientNumeratorStagedSingleWritePlan,
) {
    assert_eq!(plan.retained_slots.lde_tile, None);
    assert_eq!(plan.retained_slots.coefficient_ptrs, None);
    assert_eq!(plan.retained_slots.coefficient_sizes, None);
    assert_eq!(plan.retained_slots.coefficient_output_ptrs, None);
    let primary = plan.layout.slot(SHARED_STAGED_PRIMARY).unwrap();
    let overflow = plan.layout.slot(SHARED_STAGED_OVERFLOW).unwrap();
    let mut words = 0usize;
    for lde in staged.coefficient_ldes() {
        let slot = plan.layout.slot(retained_image_id(lde.column())).unwrap();
        let role_base = match lde.staging_role() {
            QuotientNumeratorStagingRole::Primary => primary.offset_words,
            QuotientNumeratorStagingRole::Overflow(0) => overflow.offset_words,
            role => panic!("unexpected retained FixedImage role {role:?}"),
        };
        assert_eq!(slot.offset_words, role_base + lde.role_offset_words());
        assert_eq!(slot.len_words, lde.len_words());
        words += slot.len_words;
    }
    assert_eq!(words, RETAINED_IMAGE_WORDS);
    assert_eq!(u64::try_from(words).unwrap() * 4, 3_919_863_424);
}

fn slot_spec(specs: &[ArenaSlotSpec], id: ArenaSlotId) -> ArenaSlotSpec {
    specs
        .iter()
        .copied()
        .find(|spec| spec.id == id)
        .unwrap_or_else(|| panic!("missing arena slot {id:?}"))
}

pub(crate) fn retained_image_id(column: usize) -> ArenaSlotId {
    ArenaSlotId(RETAINED_IMAGE_BASE + u32::try_from(column).unwrap())
}

fn retained_manifest_digest(
    layout: &ArenaLayout,
    staged: &QuotientNumeratorStagedSingleWritePlan,
) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(b"stwo.sn3-fixed-image-arena-manifest.v1\0");
    for lde in staged.coefficient_ldes() {
        let id = retained_image_id(lde.column());
        let slot = layout.slot(id).unwrap();
        for value in [
            u64::try_from(lde.column()).unwrap(),
            u64::from(lde.evaluation_log_size()),
            u64::from(id.0),
            u64::try_from(slot.offset_words).unwrap(),
            u64::try_from(slot.len_words).unwrap(),
            u64::try_from(slot.alignment_words).unwrap(),
        ] {
            hasher.update(&value.to_le_bytes());
        }
    }
    hasher.finalize()
}

fn push_spec(
    specs: &mut Vec<ArenaSlotSpec>,
    cursor: &mut usize,
    id: ArenaSlotId,
    len_words: usize,
    alignment_words: usize,
) {
    assert_ne!(len_words, 0);
    *cursor = cursor
        .checked_add((alignment_words - *cursor % alignment_words) % alignment_words)
        .unwrap();
    specs.push(ArenaSlotSpec {
        id,
        offset_words: *cursor,
        len_words,
        alignment_words,
    });
    *cursor = cursor.checked_add(len_words).unwrap();
}

fn output_id(group: usize, coordinate: usize) -> ArenaSlotId {
    ArenaSlotId(OUTPUT_BASE + u32::try_from(4 * group + coordinate).unwrap())
}

pub(crate) fn prepare<'a>(
    fixture: &'a BenchmarkArena,
    columns: &[QuotientNumeratorColumn],
    destinations: &[QuotientNumeratorDestination],
    slots: &QuotientNumeratorWorkspaceSlots,
    group_direct: bool,
    overflow_role_ids: &[ArenaSlotId],
) -> PreparedQuotientNumeratorGraph<'a> {
    let overflow_roles = overflow_role_ids
        .iter()
        .map(|&id| fixture.arena.bind(id).unwrap())
        .collect::<Vec<_>>();
    let arguments = (
        fixture.arena.bind(OODS_POINTS).unwrap(),
        fixture.arena.bind(OODS_VALUES).unwrap(),
        fixture.arena.bind(RANDOM_COEFFICIENT).unwrap(),
        fixture.arena.bind(SAMPLE_POINTS_OUTPUT).unwrap(),
        fixture.arena.bind(FIRST_TERMS_OUTPUT).unwrap(),
        fixture.arena.bind(TWIDDLES).unwrap(),
    );
    if group_direct {
        PreparedQuotientNumeratorGraph::prepare_staged_group_direct(
            &fixture.arena,
            retained_config(),
            columns,
            arguments.0,
            arguments.1,
            arguments.2,
            arguments.3,
            arguments.4,
            destinations,
            arguments.5,
            slots,
            &overflow_roles,
        )
        .unwrap()
    } else {
        PreparedQuotientNumeratorGraph::prepare_staged_packed_single_write(
            &fixture.arena,
            retained_config(),
            columns,
            arguments.0,
            arguments.1,
            arguments.2,
            arguments.3,
            arguments.4,
            destinations,
            arguments.5,
            slots,
            &overflow_roles,
        )
        .unwrap()
    }
}

pub(crate) fn initialize(
    fixture: &BenchmarkArena,
    topology: &[QuotientNumeratorColumnTopology],
    shape: &RetainedShape,
    points: &[CirclePoint<SecureField>],
    poison: u32,
) {
    upload(&fixture.arena, OODS_POINTS, &point_words(points));
    upload(
        &fixture.arena,
        OODS_VALUES,
        &secure_words(&oods_values(points.len())),
    );
    upload(
        &fixture.arena,
        RANDOM_COEFFICIENT,
        &secure_words(&[random_coefficient()]),
    );
    upload_affine_pattern(
        &fixture.arena,
        TWIDDLES,
        shape.control_requirements.forward_twiddle_words,
        TWIDDLE_PATTERN_SEED,
    );
    upload_affine_pattern(
        &fixture.arena,
        INVERSE_TWIDDLES,
        shape.quotient_requirements.inverse_twiddle_words,
        INVERSE_TWIDDLE_PATTERN_SEED,
    );
    for (index, (&id, column)) in fixture.source_ids.iter().zip(topology).enumerate() {
        upload_affine_pattern(
            &fixture.arena,
            id,
            source_words(column),
            source_pattern_seed(index),
        );
    }
    poison_outputs(fixture, &shape.control_requirements, poison);
}

pub(crate) fn upload(arena: &DeviceArena, slot: ArenaSlotId, words: &[u32]) {
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                arena.bind(slot).unwrap().as_void_ptr(),
                words.as_ptr().cast(),
                std::mem::size_of_val(words),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
}
