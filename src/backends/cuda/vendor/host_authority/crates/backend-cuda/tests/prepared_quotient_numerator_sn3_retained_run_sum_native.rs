//! Formal same-prepared-object SN3 A/B for the retained FixedImage numerator.
//!
//! The fixture preserves the proven `3a97d092` arena/lifetime topology. The
//! timed baseline and candidate are two launch methods on one retained
//! prepared numerator object followed by the same ordinary quotient tail.

#[allow(dead_code)]
#[path = "support/sn3_quotient_numerator_bench.rs"]
mod sn3_quotient_numerator_bench;
#[path = "support/sn3_quotient_retained_fixture.rs"]
mod sn3_quotient_retained_fixture;
#[path = "support/sn3_quotient_retained_result.rs"]
mod sn3_quotient_retained_result;
#[path = "support/sn3_quotient_retained_run_sum_ab.rs"]
mod sn3_quotient_retained_run_sum_ab;
#[path = "support/sn3_quotient_topology_fixture.rs"]
mod sn3_quotient_topology_fixture;

use sn3_quotient_retained_fixture::BenchmarkArena;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo_backend_cuda::{
    quotient_numerator_staged_single_write_plan_with_overflow_capacities,
    quotient_numerator_workspace_requirements, quotient_workspace_requirements, ArenaLayout,
    ArenaRangeSpec, ArenaSlice, ArenaSlotId, ArenaSlotSpec, CudaExecContext, CudaGraphExec,
    DeviceArena, PreparedNumeratorSchedule, PreparedQuotientGraph, PreparedQuotientNumeratorGraph,
    QuotientNumeratorColumn, QuotientNumeratorColumnSource, QuotientNumeratorColumnTopology,
    QuotientNumeratorDestination, QuotientNumeratorSourceKind,
    QuotientNumeratorStagedSingleWritePlan, QuotientNumeratorStagingRole,
    QuotientNumeratorWorkspaceConfig, QuotientNumeratorWorkspaceRequirements,
    QuotientNumeratorWorkspaceSlots, QuotientWorkspaceConfig, QuotientWorkspaceRequirements,
    QuotientWorkspaceSlots,
};

const GROUP_LOGS: [u32; 19] = [
    23, 19, 20, 6, 16, 18, 8, 7, 21, 14, 17, 11, 23, 15, 10, 4, 13, 12, 22,
];
const EXPECTED_SN3_TOPOLOGY_CONFIG: QuotientNumeratorWorkspaceConfig =
    QuotientNumeratorWorkspaceConfig {
        lifting_log_size: 24,
        log_blowup_factor: 1,
        max_lde_tile_words: 1 << 24,
    };
const SN3_QUOTIENT_CONFIG: QuotientWorkspaceConfig = QuotientWorkspaceConfig {
    lifting_log_size: 24,
    log_blowup_factor: 1,
};
const STAGED_PRIMARY_WORDS: usize = 536_870_912;
const STAGED_OVERFLOW_WORDS: usize = 452_984_832;
const STAGED_DESCRIPTOR_WORKSPACE_BYTES: u64 = 787_904;
const QUOTIENT_INCREMENTAL_ARENA_WORDS: usize = 104_857_792;
const EXPECTED_SN3_ARENA_BYTES: u64 = 46_133_748_992;
const FRI_INPUT_OUTPUT_BYTES: u64 = 268_435_456;
const RETAINED_COLUMN_COUNT: usize = 152;
const RETAINED_IMAGE_WORDS: usize = 979_965_856;
const EXPECTED_RETAINED_MANIFEST_BLAKE3: &str =
    "5fb8d1619fd55b46eb501021e4610b29d4450b42e473ae3641f1919bd927cc32";
const EXPECTED_SN3_TOPOLOGY_FIXTURE_BLAKE3: &str =
    "ea31e3ff054c8d12d32d5b84a3d712987b31bb1fd3fb044fb27758453b49fbda";
const EXPECTED_SN3_INPUT_RECIPE_BLAKE3: &str =
    "e4c2f871c2d05b81588a5407f06cb49c7ed76834d2e363d2214bd34e7defcf31";
const EXPECTED_SN3_BOUNDARY_INPUT_RECIPE_BLAKE3: &str =
    "a88aaa1f23b4c22201c9f9b1ed0aedc17bde8ababb50eae72a828a0eeab06ae9";
const INVERSE_TWIDDLE_PATTERN_SEED: u64 = 32_452_843;

const OODS_POINTS: ArenaSlotId = ArenaSlotId(100);
const OODS_VALUES: ArenaSlotId = ArenaSlotId(101);
const RANDOM_COEFFICIENT: ArenaSlotId = ArenaSlotId(102);
const SAMPLE_POINTS_OUTPUT: ArenaSlotId = ArenaSlotId(103);
const FIRST_TERMS_OUTPUT: ArenaSlotId = ArenaSlotId(104);
const TWIDDLES: ArenaSlotId = ArenaSlotId(105);
const SHARED_STAGED_PRIMARY: ArenaSlotId = ArenaSlotId(106);
const SHARED_STAGED_OVERFLOW: ArenaSlotId = ArenaSlotId(107);
const QUOTIENT_WORKSPACE_BASE: u32 = 200;
const INVERSE_TWIDDLES: ArenaSlotId = ArenaSlotId(207);
const SOURCE_BASE: u32 = 1_000;
const OUTPUT_BASE: u32 = 10_000;
const ORACLE_WORKSPACE_BASE: u32 = 1;
const RESERVED_CONTROL_WORKSPACE_BASE: u32 = 20;
const RETAINED_IMAGE_BASE: u32 = 20_000;
const ORACLE_LIVE: u16 = 0b01;
const RETAINED_LIVE: u16 = 0b10;
const BOTH_LIVE: u16 = ORACLE_LIVE | RETAINED_LIVE;

#[test]
#[ignore = "requires CUDA and the exact 42.97 GiB retained SN3 arena"]
fn sn3_retained_run_sum_same_object_cuda_event_benchmark() {
    sn3_quotient_retained_result::assert_promotion_artifacts();
    sn3_quotient_retained_run_sum_ab::run();
}

#[test]
#[ignore = "requires the sealed production CUDA artifacts and receipt"]
fn sn3_retained_run_sum_promotion_artifacts_are_exact() {
    sn3_quotient_retained_result::assert_promotion_artifacts();
}

#[test]
fn sn3_retained_run_sum_shape_is_exact() {
    sn3_quotient_retained_fixture::assert_host_shape();
}

fn source_words(column: &QuotientNumeratorColumnTopology) -> usize {
    let log_size = column.coefficient_log_size
        + u32::from(column.source_kind == QuotientNumeratorSourceKind::Evaluation);
    1usize << log_size
}

fn oods_values(count: usize) -> Vec<SecureField> {
    (0..count)
        .map(|index| {
            let value = index as u32 * 16 + 1;
            SecureField::from_u32_unchecked(value, value + 2, value + 4, value + 6)
        })
        .collect()
}

fn random_coefficient() -> SecureField {
    SecureField::from_u32_unchecked(307, 311, 313, 317)
}

fn point_words(points: &[CirclePoint<SecureField>]) -> Vec<u32> {
    points
        .iter()
        .flat_map(|point| [point.x, point.y])
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}

fn secure_words(values: &[SecureField]) -> Vec<u32> {
    values
        .iter()
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}
