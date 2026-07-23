#[path = "support/sn3_quotient_topology_fixture.rs"]
mod sn3_quotient_topology_fixture;

use std::collections::BTreeSet;

use sn3_quotient_topology_fixture::load_sn3_topology_fixture;
use stwo_backend_cuda::{
    quotient_numerator_run_sum_plan,
    quotient_numerator_staged_single_write_plan_with_overflow_capacities,
    QuotientNumeratorRunSumLiveness, QuotientNumeratorWorkspaceConfig,
};

const FIXTURE_BLAKE3: &str = "ea31e3ff054c8d12d32d5b84a3d712987b31bb1fd3fb044fb27758453b49fbda";
const OVERFLOW_WORDS: usize = 452_984_832;

#[test]
fn sealed_sn3_group0_run_sum_receipt_is_exact_and_zero_incremental() {
    let fixture = load_sn3_topology_fixture(FIXTURE_BLAKE3);
    assert_eq!(fixture.digest.to_hex().as_str(), FIXTURE_BLAKE3);
    let config = QuotientNumeratorWorkspaceConfig {
        max_lde_tile_words: 32 * (1usize << fixture.config.lifting_log_size),
        ..fixture.config
    };
    let staged = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
        config,
        &fixture.topology,
        &[OVERFLOW_WORDS],
    )
    .unwrap();
    let mut selected = None;
    'selection: for target_group in 0..staged.requirements().groups.len() {
        for victim_group in target_group + 1..staged.requirements().groups.len() {
            let capacity = staged.requirements().groups[victim_group].value_words;
            let Ok(candidate) = quotient_numerator_run_sum_plan(
                &staged,
                target_group,
                victim_group,
                QuotientNumeratorRunSumLiveness {
                    same_stream_canonical_group_order: true,
                    external_destination_ids_unique: true,
                    victim_unread_before_own_producer: true,
                    victim_fully_overwritten_by_own_producer: true,
                    downstream_consumers_after_all_group_producers: true,
                    victim_coordinate_capacity_words: [capacity; 4],
                },
            ) else {
                continue;
            };
            if candidate.add_units_saved != 0 {
                selected = Some(candidate);
                break 'selection;
            }
        }
    }
    let selected = selected.unwrap();
    assert_eq!((selected.target_group, selected.victim_group), (0, 12));

    let receipt = quotient_numerator_run_sum_plan(
        &staged,
        0,
        12,
        QuotientNumeratorRunSumLiveness {
            same_stream_canonical_group_order: true,
            external_destination_ids_unique: true,
            victim_unread_before_own_producer: true,
            victim_fully_overwritten_by_own_producer: true,
            downstream_consumers_after_all_group_producers: true,
            victim_coordinate_capacity_words: [1 << 23; 4],
        },
    )
    .unwrap();
    assert_eq!(receipt.target_group_log_size, 23);
    assert_eq!(receipt.victim_group_log_size, 23);
    assert_eq!(receipt.target_term_begin, 0);
    assert_eq!(receipt.target_term_end, 5_885);
    assert_eq!(receipt.precomputed_term_count, 5_718);
    assert_eq!(receipt.direct_term_count, 167);
    assert_eq!(receipt.manifest.run_count, 17);
    assert_eq!(receipt.manifest.direct_term_begin, 5_718);
    assert_eq!(receipt.manifest.direct_term_end, 5_885);
    let actual = receipt
        .manifest
        .active_entries()
        .iter()
        .map(|entry| {
            (
                entry.source_log_size,
                entry.term_count(),
                entry.scratch_offset_words,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        [
            (4, 22, 0),
            (6, 41, 16),
            (7, 7, 80),
            (8, 21, 208),
            (10, 248, 464),
            (11, 315, 1_488),
            (12, 34, 3_536),
            (13, 399, 7_632),
            (14, 39, 15_824),
            (15, 10, 32_208),
            (16, 732, 64_976),
            (17, 29, 130_512),
            (18, 543, 261_584),
            (19, 1_293, 523_728),
            (20, 1_225, 1_048_016),
            (21, 620, 2_096_592),
            (22, 140, 4_193_744),
        ]
    );
    assert_eq!(receipt.scratch_words_per_coordinate, 8_388_048);
    assert_eq!(receipt.margin_words_per_coordinate, [560; 4]);
    assert_eq!(receipt.baseline_row_terms, 49_366_958_080);
    assert_eq!(receipt.precompute_products, 4_049_247_264);
    assert_eq!(receipt.direct_products, 1_400_897_536);
    assert_eq!(receipt.candidate_products, 5_450_144_800);
    assert_eq!(receipt.expansion_adds, 142_606_336);
    assert_eq!(receipt.candidate_add_units, 5_592_751_136);
    assert_eq!(receipt.products_saved, 43_916_813_280);
    assert_eq!(receipt.add_units_saved, 43_774_206_944);

    let descriptors = &staged.term_descriptors()[..receipt.target_term_end as usize * 3];
    let all_sources = descriptors
        .chunks_exact(3)
        .map(|descriptor| (descriptor[0], descriptor[2]))
        .collect::<BTreeSet<_>>();
    let direct_sources = descriptors[receipt.manifest.direct_term_begin as usize * 3..]
        .chunks_exact(3)
        .map(|descriptor| (descriptor[0], descriptor[2]))
        .collect::<BTreeSet<_>>();
    assert_eq!(all_sources.len(), 5_877);
    assert_eq!(direct_sources.len(), 159);
    assert!(direct_sources
        .iter()
        .all(|(_, source_log)| *source_log == 23));

    assert_eq!(
        blake3::Hash::from_bytes(receipt.identity).to_hex().as_str(),
        "3a32bee348682d156f62064dd1622f23a4ec881fda64c81a0054eaa42c7464c9"
    );
}
