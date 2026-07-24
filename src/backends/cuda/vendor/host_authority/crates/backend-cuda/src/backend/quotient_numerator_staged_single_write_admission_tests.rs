use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;

use super::*;
use crate::backend::exec_context::{ArenaLayout, ArenaRangeSpec, ArenaSlotId, ArenaSlotSpec};
use crate::backend::prepared_quotient_numerator::{
    QuotientNumeratorSourceKind, QuotientOodsSample,
};

#[test]
fn exact_sn_staging_footprints_fit_two_epoch_disjoint_roles() {
    for fixture in exact_sn_fixtures() {
        let topology = fixture.topology();
        let plan = quotient_numerator_staged_single_write_plan(fixture.config(), &topology)
            .expect("sealed SN staging histogram must be admitted");
        let report = plan.report();
        assert_eq!(report.coefficient_source_count, fixture.coefficient_sources);
        assert_eq!(report.total_staging_words, fixture.total_staging_words);
        assert_eq!(
            report.factor32_staging_words,
            fixture.factor32_staging_words
        );
        assert_eq!(report.primary_staging_words, fixture.primary_staging_words);
        assert_eq!(
            report.overflow_staging_words,
            fixture.overflow_staging_words
        );
        assert_eq!(
            report.incremental_staging_words_over_factor32,
            fixture.incremental_staging_words
        );
        assert!(
            report.overflow_staging_words <= fixture.released_commit_slab_words,
            "{} overflow must fit the one-slab-released role",
            fixture.name
        );
        assert_eq!(
            report.primary_staging_words + report.unused_factor32_staging_words,
            report.factor32_staging_words
        );
        assert_role_ranges(&plan, report);
        assert_ordered_launch_manifest(&plan);
    }
}

#[test]
fn overflow_role_reuses_the_released_commit_slab_only_across_disjoint_epochs() {
    const PRIMARY: ArenaSlotId = ArenaSlotId(1);
    const RELEASED_COMMIT: ArenaSlotId = ArenaSlotId(2);
    const OVERFLOW: ArenaSlotId = ArenaSlotId(3);
    const PRIMARY_WORDS: usize = 956_301_312;
    const RELEASED_WORDS: usize = 3_221_225_472 / 4;
    const MAX_OVERFLOW_WORDS: usize = 452_984_832;
    const COMMIT_EPOCH: u16 = 0b01;
    const QUOTIENT_EPOCH: u16 = 0b10;

    let mut ranges = [
        range(PRIMARY, 0, PRIMARY_WORDS, QUOTIENT_EPOCH),
        range(RELEASED_COMMIT, PRIMARY_WORDS, RELEASED_WORDS, COMMIT_EPOCH),
        range(OVERFLOW, PRIMARY_WORDS, MAX_OVERFLOW_WORDS, QUOTIENT_EPOCH),
    ];
    // SAFETY: the two bits model the only commit and quotient lifetimes in
    // this address-free ownership proof; captured execution cannot cross the
    // transcript boundary between them.
    let layout =
        unsafe { ArenaLayout::new_reused(PRIMARY_WORDS + RELEASED_WORDS, &ranges) }.unwrap();
    assert_eq!(
        layout.slot(RELEASED_COMMIT).unwrap().offset_words,
        layout.slot(OVERFLOW).unwrap().offset_words
    );
    assert!(MAX_OVERFLOW_WORDS < RELEASED_WORDS);

    ranges[2].live_mask = COMMIT_EPOCH | QUOTIENT_EPOCH;
    assert!(unsafe { ArenaLayout::new_reused(PRIMARY_WORDS + RELEASED_WORDS, &ranges) }.is_err());
}

fn range(id: ArenaSlotId, offset_words: usize, len_words: usize, live_mask: u16) -> ArenaRangeSpec {
    ArenaRangeSpec {
        slot: ArenaSlotSpec {
            id,
            offset_words,
            len_words,
            alignment_words: 1,
        },
        live_mask,
    }
}

fn assert_role_ranges(
    plan: &QuotientNumeratorStagedSingleWritePlan,
    report: QuotientNumeratorStagedSingleWriteReport,
) {
    for role in [
        QuotientNumeratorStagingRole::Primary,
        QuotientNumeratorStagingRole::Overflow(0),
    ] {
        let mut prior_end = 0;
        for lde in plan
            .coefficient_ldes()
            .iter()
            .filter(|lde| lde.staging_role() == role)
        {
            assert_eq!(lde.role_offset_words(), prior_end);
            prior_end = lde.role_end_words();
        }
        let expected = match role {
            QuotientNumeratorStagingRole::Primary => report.primary_staging_words,
            QuotientNumeratorStagingRole::Overflow(0) => report.overflow_staging_words,
            QuotientNumeratorStagingRole::Overflow(_) => unreachable!(),
        };
        assert_eq!(prior_end, expected);
    }
}

fn assert_ordered_launch_manifest(plan: &QuotientNumeratorStagedSingleWritePlan) {
    let mut covered = 0;
    let mut saw_accumulation = false;
    for operation in plan.operations() {
        match operation {
            QuotientNumeratorStagedOperation::MaterializeLdes(launch) => {
                assert!(!saw_accumulation);
                assert_eq!(launch.first_lde(), covered);
                let end = covered + launch.lde_count();
                assert!(plan.coefficient_ldes()[covered..end]
                    .iter()
                    .all(|lde| lde.evaluation_log_size() == launch.evaluation_log_size()));
                covered = end;
            }
            QuotientNumeratorStagedOperation::AccumulatePackedRows { .. } => {
                assert!(!saw_accumulation);
                saw_accumulation = true;
                assert_eq!(covered, plan.coefficient_ldes().len());
            }
        }
    }
    assert!(saw_accumulation);
}

#[derive(Clone, Copy)]
struct ExactSnFixture {
    name: &'static str,
    lifting_log_size: u32,
    histogram: &'static [(u32, usize)],
    coefficient_sources: usize,
    total_staging_words: usize,
    factor32_staging_words: usize,
    primary_staging_words: usize,
    overflow_staging_words: usize,
    incremental_staging_words: usize,
    released_commit_slab_words: usize,
}

impl ExactSnFixture {
    fn config(self) -> QuotientNumeratorWorkspaceConfig {
        QuotientNumeratorWorkspaceConfig {
            lifting_log_size: self.lifting_log_size,
            log_blowup_factor: 1,
            max_lde_tile_words: 32 * (1 << self.lifting_log_size),
        }
    }

    fn topology(self) -> Vec<QuotientNumeratorColumnTopology> {
        let mut input_index = 0u32;
        self.histogram
            .iter()
            .flat_map(|&(log_size, count)| {
                (0..count).map(move |_| {
                    let sample = QuotientOodsSample {
                        input_index,
                        shape_point: SECURE_FIELD_CIRCLE_GEN.mul(u128::from(input_index) + 1),
                    };
                    input_index += 1;
                    QuotientNumeratorColumnTopology {
                        coefficient_log_size: log_size,
                        source_kind: QuotientNumeratorSourceKind::Coefficients,
                        samples: vec![sample],
                    }
                })
            })
            .collect()
    }
}

// Filled from the four sealed ReplacementV1 topology fixtures. The fixture
// digests and derivation receipt live in the Stage-4 evidence artifact.
fn exact_sn_fixtures() -> [ExactSnFixture; 4] {
    const RELEASED_WORDS: usize = 3_221_225_472 / 4;
    [
        ExactSnFixture {
            name: "SN1",
            lifting_log_size: 25,
            histogram: &SN1,
            coefficient_sources: 152,
            total_staging_words: 980_225_952,
            factor32_staging_words: 956_301_312,
            primary_staging_words: 946_671_520,
            overflow_staging_words: 33_554_432,
            incremental_staging_words: 23_924_640,
            released_commit_slab_words: RELEASED_WORDS,
        },
        ExactSnFixture {
            name: "SN2",
            lifting_log_size: 24,
            histogram: &SN2,
            coefficient_sources: 153,
            total_staging_words: 976_852_896,
            factor32_staging_words: 536_870_912,
            primary_staging_words: 523_868_064,
            overflow_staging_words: 452_984_832,
            incremental_staging_words: 439_981_984,
            released_commit_slab_words: RELEASED_WORDS,
        },
        ExactSnFixture {
            name: "SN3",
            lifting_log_size: 24,
            histogram: &SN3,
            coefficient_sources: 152,
            total_staging_words: 979_965_856,
            factor32_staging_words: 536_870_912,
            primary_staging_words: 526_981_024,
            overflow_staging_words: 452_984_832,
            incremental_staging_words: 443_094_944,
            released_commit_slab_words: RELEASED_WORDS,
        },
        ExactSnFixture {
            name: "SN4",
            lifting_log_size: 25,
            histogram: &SN4,
            coefficient_sources: 152,
            total_staging_words: 980_145_056,
            factor32_staging_words: 956_301_312,
            primary_staging_words: 946_590_624,
            overflow_staging_words: 33_554_432,
            incremental_staging_words: 23_843_744,
            released_commit_slab_words: RELEASED_WORDS,
        },
    ]
}

const SN1: [(u32, usize); 15] = [
    (4, 17),
    (6, 31),
    (7, 2),
    (8, 6),
    (11, 1),
    (12, 1),
    (13, 1),
    (14, 7),
    (15, 5),
    (16, 8),
    (17, 1),
    (18, 10),
    (20, 4),
    (22, 1),
    (23, 57),
];
const SN2: [(u32, usize); 16] = [
    (4, 17),
    (6, 31),
    (7, 2),
    (8, 6),
    (10, 1),
    (11, 1),
    (12, 1),
    (13, 1),
    (14, 6),
    (15, 6),
    (16, 8),
    (18, 10),
    (19, 1),
    (20, 4),
    (21, 1),
    (23, 57),
];
const SN3: [(u32, usize); 15] = [
    (4, 17),
    (6, 31),
    (7, 2),
    (8, 6),
    (10, 1),
    (11, 1),
    (12, 1),
    (13, 1),
    (14, 7),
    (15, 5),
    (16, 8),
    (18, 10),
    (20, 4),
    (22, 1),
    (23, 57),
];
const SN4: [(u32, usize); 15] = [
    (4, 17),
    (6, 31),
    (7, 2),
    (8, 6),
    (9, 1),
    (11, 1),
    (12, 1),
    (14, 7),
    (15, 6),
    (16, 7),
    (17, 1),
    (18, 10),
    (20, 4),
    (22, 1),
    (23, 57),
];
