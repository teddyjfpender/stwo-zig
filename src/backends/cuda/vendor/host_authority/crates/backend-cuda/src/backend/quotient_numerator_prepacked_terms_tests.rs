use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;

use super::*;
use crate::backend::prepared_quotient_numerator::{
    QuotientNumeratorColumnTopology, QuotientNumeratorSourceKind, QuotientNumeratorWorkspaceConfig,
    QuotientOodsSample,
};
use crate::backend::quotient_numerator_staged_single_write::{
    quotient_numerator_staged_single_write_plan, QuotientNumeratorStagedSingleWritePlan,
};

fn config() -> QuotientNumeratorWorkspaceConfig {
    QuotientNumeratorWorkspaceConfig {
        lifting_log_size: 10,
        log_blowup_factor: 2,
        max_lde_tile_words: 32 * (1 << 10),
    }
}

fn topology(columns_per_group: usize) -> Vec<QuotientNumeratorColumnTopology> {
    [3u128, 5]
        .into_iter()
        .flat_map(|multiple| {
            (0..columns_per_group).map(move |column| QuotientNumeratorColumnTopology {
                coefficient_log_size: 2 + column as u32 % 4,
                source_kind: if column % 3 == 0 {
                    QuotientNumeratorSourceKind::Coefficients
                } else {
                    QuotientNumeratorSourceKind::Evaluation
                },
                samples: vec![QuotientOodsSample {
                    input_index: (multiple as u32) * 100 + column as u32,
                    shape_point: SECURE_FIELD_CIRCLE_GEN.mul(multiple),
                }],
            })
        })
        .collect()
}

#[test]
fn layout_reuses_only_the_dead_term_point_extent() {
    let plan = quotient_numerator_staged_single_write_plan(config(), &topology(6)).unwrap();
    let layout = quotient_numerator_prepacked_term_layout(&plan).unwrap();
    assert_eq!(layout.term_count, 12);
    assert_eq!(layout.group_count, 2);
    assert_eq!(layout.term_words, 12 * 7);
    assert_eq!(layout.group_b_offset_words, 12 * 7);
    assert_eq!(layout.group_b_words, 2 * 4);
    assert_eq!(layout.status_offset_words, 92);
    assert_eq!(layout.status_words, 1);
    assert_eq!(layout.used_words, 93);
    assert_eq!(layout.term_point_capacity_words, 12 * 8);
    assert_eq!(layout.spare_words(), 3);
}

#[test]
fn layout_fails_closed_when_group_b_does_not_fit_the_dead_tail() {
    let plan = quotient_numerator_staged_single_write_plan(config(), &topology(1)).unwrap();
    assert_eq!(
        quotient_numerator_prepacked_term_layout(&plan),
        Err(
            QuotientNumeratorPrepackedTermError::InsufficientDeadTermPointWords {
                required_words: 23,
                available_words: 16,
            }
        )
    );
}

#[test]
fn status_code_contract_is_stable_unique_and_nonzero_on_error() {
    assert_eq!(QuotientNumeratorPrepackedStatusCode::Success.as_u32(), 0);
    let codes = [
        QuotientNumeratorPrepackedStatusCode::PrepareGroupOffsetsNotCanonical,
        QuotientNumeratorPrepackedStatusCode::PrepareSourceOutOfBounds,
        QuotientNumeratorPrepackedStatusCode::PrepareTermOutOfBounds,
        QuotientNumeratorPrepackedStatusCode::PrepareSourceLogOutOfBounds,
        QuotientNumeratorPrepackedStatusCode::PrepareNullSource,
        QuotientNumeratorPrepackedStatusCode::PrepareGroupRangeOutOfBounds,
        QuotientNumeratorPrepackedStatusCode::PrepareGroupTermOutOfBounds,
        QuotientNumeratorPrepackedStatusCode::HotRowOffsetsNotCanonical,
        QuotientNumeratorPrepackedStatusCode::HotGroupRowShapeInvalid,
        QuotientNumeratorPrepackedStatusCode::HotGroupTermRangeInvalid,
        QuotientNumeratorPrepackedStatusCode::HotSourceLogOutOfBounds,
        QuotientNumeratorPrepackedStatusCode::HotNullSource,
    ]
    .map(QuotientNumeratorPrepackedStatusCode::as_u32);
    assert_eq!(codes, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
}

#[test]
fn prepacked_formula_matches_legacy_term_association_across_randomized_rows() {
    let plan = quotient_numerator_staged_single_write_plan(config(), &topology(6)).unwrap();
    let mut state = 0x7b2d_90c4_4217_e8a1u64;
    for _case in 0..128 {
        let coefficients = (0..plan.requirements().term_count)
            .map(|_| QuotientNumeratorLineCoefficientsWords {
                b: std::array::from_fn(|_| next_m31(&mut state)),
                c: std::array::from_fn(|_| next_m31(&mut state)),
            })
            .collect::<Vec<_>>();
        let sources = plan
            .sources()
            .iter()
            .map(|source| {
                (0..1usize << source.evaluation_log_size())
                    .map(|_| next_m31(&mut state))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let packed = quotient_numerator_prepacked_term_oracle(&plan, &coefficients).unwrap();
        assert_eq!(packed.plan_identity().len(), 32);

        for (group, requirements) in plan.requirements().groups.iter().enumerate() {
            for row in 0..requirements.value_words {
                let expected = legacy_row(&plan, &coefficients, &sources, group, row);
                let actual =
                    quotient_numerator_prepacked_row_oracle(&plan, &packed, &sources, group, row)
                        .unwrap();
                assert_eq!(actual, expected);
            }
        }
    }
}

#[test]
fn pre_sum_and_descriptor_order_are_mutation_observable() {
    let plan = quotient_numerator_staged_single_write_plan(config(), &topology(6)).unwrap();
    let coefficients = (0..plan.requirements().term_count)
        .map(|term| QuotientNumeratorLineCoefficientsWords {
            b: [term as u32 + 1, 0, 0, 0],
            c: [term as u32 + 17, 0, 0, 0],
        })
        .collect::<Vec<_>>();
    let packed = quotient_numerator_prepacked_term_oracle(&plan, &coefficients).unwrap();

    for group in 0..plan.requirements().groups.len() {
        let begin = plan.group_offsets()[group] as usize;
        let end = plan.group_offsets()[group + 1] as usize;
        let expected_b = plan.term_descriptors()
            [begin * SOURCE_DESCRIPTOR_WORDS..end * SOURCE_DESCRIPTOR_WORDS]
            .chunks_exact(SOURCE_DESCRIPTOR_WORDS)
            .fold(0, |sum, descriptor| {
                m31_add(
                    sum,
                    coefficients[descriptor[TERM_ORDINAL_WORD] as usize].b[0],
                )
            });
        assert_eq!(packed.group_b()[group][0], expected_b);
        for (record, descriptor) in packed.terms()[begin..end].iter().zip(
            plan.term_descriptors()[begin * SOURCE_DESCRIPTOR_WORDS..end * SOURCE_DESCRIPTOR_WORDS]
                .chunks_exact(SOURCE_DESCRIPTOR_WORDS),
        ) {
            assert_eq!(record.source_ordinal(), descriptor[SOURCE_ORDINAL_WORD]);
            assert_eq!(record.source_log_size(), descriptor[SOURCE_LOG_WORD]);
            assert_eq!(
                record.c(),
                coefficients[descriptor[TERM_ORDINAL_WORD] as usize].c
            );
        }
    }

    let sources = plan
        .sources()
        .iter()
        .map(|source| vec![1; 1usize << source.evaluation_log_size()])
        .collect::<Vec<_>>();
    let baseline = quotient_numerator_prepacked_row_oracle(&plan, &packed, &sources, 0, 0).unwrap();
    let mut mutated = coefficients.clone();
    let first_group_term = plan.term_descriptors()[TERM_ORDINAL_WORD] as usize;
    mutated[first_group_term].c[0] = m31_add(mutated[first_group_term].c[0], 1);
    let mutated = quotient_numerator_prepacked_term_oracle(&plan, &mutated).unwrap();
    assert_ne!(
        quotient_numerator_prepacked_row_oracle(&plan, &mutated, &sources, 0, 0).unwrap(),
        baseline
    );
}

#[test]
fn modulus_alias_normalizes_and_larger_words_fail_closed() {
    let plan = quotient_numerator_staged_single_write_plan(config(), &topology(6)).unwrap();
    let coefficients = vec![
        QuotientNumeratorLineCoefficientsWords {
            b: [M31_MODULUS; 4],
            c: [M31_MODULUS; 4],
        };
        plan.requirements().term_count
    ];
    let packed = quotient_numerator_prepacked_term_oracle(&plan, &coefficients).unwrap();
    let sources = plan
        .sources()
        .iter()
        .map(|source| vec![M31_MODULUS; 1usize << source.evaluation_log_size()])
        .collect::<Vec<_>>();
    assert_eq!(
        quotient_numerator_prepacked_row_oracle(&plan, &packed, &sources, 0, 0).unwrap(),
        [0; 4]
    );

    let mut invalid = coefficients;
    invalid[0].c[0] = M31_MODULUS + 1;
    assert!(matches!(
        quotient_numerator_prepacked_term_oracle(&plan, &invalid),
        Err(QuotientNumeratorPrepackedTermError::NonCanonicalWord {
            term: 0,
            coordinate: 4,
            value
        }) if value == M31_MODULUS + 1
    ));
}

#[test]
fn same_shape_different_source_plan_cannot_reuse_an_oracle() {
    let topology_a = topology(6);
    let mut topology_b = topology_a.clone();
    topology_b[0].source_kind = QuotientNumeratorSourceKind::Evaluation;
    let plan_a = quotient_numerator_staged_single_write_plan(config(), &topology_a).unwrap();
    let plan_b = quotient_numerator_staged_single_write_plan(config(), &topology_b).unwrap();
    assert_eq!(
        plan_a.requirements().term_count,
        plan_b.requirements().term_count
    );
    assert_eq!(plan_a.group_offsets(), plan_b.group_offsets());
    assert_eq!(
        plan_a.packed_group_row_offsets(),
        plan_b.packed_group_row_offsets()
    );

    let coefficients = vec![
        QuotientNumeratorLineCoefficientsWords {
            b: [1; 4],
            c: [2; 4],
        };
        plan_a.requirements().term_count
    ];
    let packed = quotient_numerator_prepacked_term_oracle(&plan_a, &coefficients).unwrap();
    let sources = plan_b
        .sources()
        .iter()
        .map(|source| vec![3; 1usize << source.evaluation_log_size()])
        .collect::<Vec<_>>();
    assert!(matches!(
        quotient_numerator_prepacked_row_oracle(&plan_b, &packed, &sources, 0, 0),
        Err(QuotientNumeratorPrepackedTermError::DescriptorInvariant(
            "packed plan identity differs from the staged plan"
        ))
    ));
}

#[test]
fn same_shape_different_oods_points_cannot_reuse_an_oracle() {
    let topology_a = topology(6);
    let mut topology_b = topology_a.clone();
    for column in &mut topology_b[..6] {
        column.samples[0].shape_point = SECURE_FIELD_CIRCLE_GEN.mul(7u128);
    }
    let plan_a = quotient_numerator_staged_single_write_plan(config(), &topology_a).unwrap();
    let plan_b = quotient_numerator_staged_single_write_plan(config(), &topology_b).unwrap();
    assert_eq!(
        quotient_numerator_prepacked_term_layout(&plan_a).unwrap(),
        quotient_numerator_prepacked_term_layout(&plan_b).unwrap()
    );

    let coefficients = vec![
        QuotientNumeratorLineCoefficientsWords {
            b: [1; 4],
            c: [2; 4],
        };
        plan_a.requirements().term_count
    ];
    let packed = quotient_numerator_prepacked_term_oracle(&plan_a, &coefficients).unwrap();
    let sources = plan_b
        .sources()
        .iter()
        .map(|source| vec![3; 1usize << source.evaluation_log_size()])
        .collect::<Vec<_>>();
    assert!(matches!(
        quotient_numerator_prepacked_row_oracle(&plan_b, &packed, &sources, 0, 0),
        Err(QuotientNumeratorPrepackedTermError::DescriptorInvariant(
            "packed plan identity differs from the staged plan"
        ))
    ));
}

fn legacy_row(
    plan: &QuotientNumeratorStagedSingleWritePlan,
    coefficients: &[QuotientNumeratorLineCoefficientsWords],
    sources: &[Vec<u32>],
    group: usize,
    row: usize,
) -> [u32; 4] {
    let group_log = plan.requirements().groups[group].log_size;
    let begin = plan.group_offsets()[group] as usize;
    let end = plan.group_offsets()[group + 1] as usize;
    let mut numerator = [0; 4];
    for descriptor in plan.term_descriptors()
        [begin * SOURCE_DESCRIPTOR_WORDS..end * SOURCE_DESCRIPTOR_WORDS]
        .chunks_exact(SOURCE_DESCRIPTOR_WORDS)
    {
        let source_log = descriptor[SOURCE_LOG_WORD];
        let source_row = (row >> (group_log - source_log + 1) << 1) + (row & 1);
        let source = &sources[descriptor[SOURCE_ORDINAL_WORD] as usize];
        let coefficient = coefficients[descriptor[TERM_ORDINAL_WORD] as usize];
        for coordinate in 0..4 {
            numerator[coordinate] = m31_add(
                numerator[coordinate],
                m31_sub(
                    m31_mul(coefficient.c[coordinate], source[source_row]),
                    coefficient.b[coordinate],
                ),
            );
        }
    }
    numerator
}

fn next_m31(state: &mut u64) -> u32 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (*state % u64::from(M31_MODULUS)) as u32
}
