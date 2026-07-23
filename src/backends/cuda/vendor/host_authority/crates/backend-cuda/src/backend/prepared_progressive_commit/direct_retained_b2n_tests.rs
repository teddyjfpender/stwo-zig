use super::*;
use crate::backend::progressive_commit::{
    ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
};
use crate::backend::progressive_ntt_leaf_fusion::ProgressiveNttLeafFusionMode;

fn commit(blowup: u32) -> CommitProgram {
    CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: blowup,
            lifting_log_size: 7,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 0,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: 7,
            log_blowup_factor: blowup,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: vec![3, 3, 4],
                retain_evaluations: true,
            }],
        },
        ProgressiveNttLeafFusionMode::Separate,
        false,
    )
    .unwrap()
}

fn slots(batch_count: usize) -> ProgressiveCommitWorkspaceSlots {
    ProgressiveCommitWorkspaceSlots {
        leaves: ProgressiveLeafWorkspaceSlots {
            lde_scratch: None,
            state_ping: ArenaSlotId(100),
            state_pong: None,
            leaf_hashes: ArenaSlotId(101),
            batches: (0..batch_count)
                .map(|batch| {
                    let base = 10 + u32::try_from(batch).unwrap() * 3;
                    ProgressiveBatchSlots {
                        coefficient_ptrs: ArenaSlotId(base),
                        coefficient_sizes: ArenaSlotId(base + 1),
                        output_ptrs: ArenaSlotId(base + 2),
                    }
                })
                .collect(),
        },
        merkle: MerkleFromLeavesSlots {
            leaves: ArenaSlotId(101),
            merkle_scratch: None,
            retained_layers: vec![],
            tail_level_ptrs: None,
            tail_outputs: vec![],
        },
    }
}

fn layer_offset(log_n: u32, stage: u32) -> usize {
    let mut layer_size = 1usize;
    let mut offset = (1usize << log_n) / 2 - 2;
    for _ in 1..stage {
        layer_size <<= 1;
        offset -= layer_size;
    }
    offset
}

fn stagewise_n2b_interval(
    values: &[BaseField],
    log_n: u32,
    first_stage: u32,
    last_stage: u32,
    twiddles: &[BaseField],
) -> Vec<BaseField> {
    let mut output = values.to_vec();
    for stage in first_stage..=last_stage {
        let stride = 1usize << (log_n - stage);
        let offset = layer_offset(log_n, stage);
        for gid in 0..output.len() / 2 {
            let group = gid & (stride - 1);
            let pair = gid >> (log_n - stage);
            let left_index = group + pair * 2 * stride;
            let right_index = left_index + stride;
            let left = output[left_index];
            let product = twiddles[offset + pair] * output[right_index];
            output[left_index] = left + product;
            output[right_index] = left - product;
        }
    }
    output
}

fn rectangular_n2b_interval(
    values: &[BaseField],
    log_n: u32,
    log_values_per_thread: u32,
    log_warps_per_block: u32,
    twiddles: &[BaseField],
) -> Vec<BaseField> {
    let first_stage = 2;
    let stages = log_values_per_thread + log_warps_per_block;
    let last_stage = first_stage + stages - 1;
    let min_stride = 1usize << (log_n - last_stage);
    let values_per_thread = 1usize << log_values_per_thread;
    let warps = 1usize << log_warps_per_block;
    let grid_x = min_stride / 32;
    let grid_y = values.len() / (min_stride << stages);
    let mut output = vec![BaseField::from_u32_unchecked(0); values.len()];
    let mut written = vec![false; values.len()];

    for block_y in 0..grid_y {
        for block_x in 0..grid_x {
            let block_start = (block_x << 5) + (block_y << (log_n - last_stage + stages));
            let mut shared = vec![BaseField::from_u32_unchecked(0); 32usize << stages];

            for old_warp in 0..warps {
                for lane in 0..32usize {
                    let offset = old_warp * min_stride + lane;
                    let mut registers = (0..values_per_thread)
                        .map(|i| {
                            values[block_start + i * (min_stride << log_warps_per_block) + offset]
                        })
                        .collect::<Vec<_>>();
                    for stage in first_stage..first_stage + log_values_per_thread {
                        let log_stride = log_values_per_thread - 1 - (stage - first_stage);
                        let stride = 1usize << log_stride;
                        for gid in 0..values_per_thread / 2 {
                            let group = gid & (stride - 1);
                            let pair = gid >> log_stride;
                            let left_index = group + (pair << (log_stride + 1));
                            let right_index = left_index + stride;
                            let outer = (block_start + offset) >> (1 + log_n - stage);
                            let product = twiddles[layer_offset(log_n, stage) + pair + outer]
                                * registers[right_index];
                            let left = registers[left_index];
                            registers[left_index] = left + product;
                            registers[right_index] = left - product;
                        }
                    }
                    for (i, value) in registers.into_iter().enumerate() {
                        shared[lane + (i << (5 + log_warps_per_block)) + (old_warp << 5)] = value;
                    }
                }
            }

            for new_warp in 0..warps {
                for lane in 0..32usize {
                    let mut registers = (0..values_per_thread)
                        .map(|i| {
                            shared[lane + (i << 5) + (new_warp << (5 + log_values_per_thread))]
                        })
                        .collect::<Vec<_>>();
                    let offset = new_warp * (min_stride << log_values_per_thread) + lane;
                    for stage in first_stage + log_values_per_thread..=last_stage {
                        let log_stride =
                            log_warps_per_block - 1 - (stage - first_stage - log_values_per_thread);
                        let stride = 1usize << log_stride;
                        for gid in 0..values_per_thread / 2 {
                            let group = gid & (stride - 1);
                            let pair = gid >> log_stride;
                            let left_index = group + (pair << (log_stride + 1));
                            let right_index = left_index + stride;
                            let outer = (block_start + offset) >> (1 + log_n - stage);
                            let product = twiddles[layer_offset(log_n, stage) + pair + outer]
                                * registers[right_index];
                            let left = registers[left_index];
                            registers[left_index] = left + product;
                            registers[right_index] = left - product;
                        }
                    }
                    for (i, value) in registers.into_iter().enumerate() {
                        let address = block_start + i * min_stride + offset;
                        assert!(!written[address]);
                        output[address] = value;
                        written[address] = true;
                    }
                }
            }
        }
    }
    assert!(written.into_iter().all(|value| value));
    output
}

fn stage_one_images(words: usize) -> Vec<Vec<BaseField>> {
    let half = words / 2;
    let zero = vec![0u32; half];
    let mut impulse = zero.clone();
    impulse[half / 3] = 1;
    let carry_heavy = (0..half)
        .map(|index| if index % 2 == 0 { P - 1 } else { P - 2 })
        .collect::<Vec<_>>();
    let mut state = 0x9e37_79b9u32;
    let random = (0..half)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state % P
        })
        .collect::<Vec<_>>();
    [zero, impulse, carry_heavy, random]
        .into_iter()
        .map(|half| {
            half.iter()
                .chain(&half)
                .copied()
                .map(BaseField::from_u32_unchecked)
                .collect()
        })
        .collect()
}

#[test]
fn rectangular_first_intervals_match_independent_stagewise_arithmetic() {
    for (log_n, log_values_per_thread, log_warps_per_block) in [(13, 3, 2), (15, 4, 3)] {
        let words = 1usize << log_n;
        let twiddles = (0..words / 2)
            .map(|index| {
                BaseField::from_u32_unchecked(
                    ((index as u64 * 0x45d9_f3b + 17) % u64::from(P)) as u32,
                )
            })
            .collect::<Vec<_>>();
        let last_stage = 1 + log_values_per_thread + log_warps_per_block;
        for (case, stage_one) in stage_one_images(words).into_iter().enumerate() {
            let expected = stagewise_n2b_interval(&stage_one, log_n, 2, last_stage, &twiddles);
            let actual = rectangular_n2b_interval(
                &stage_one,
                log_n,
                log_values_per_thread,
                log_warps_per_block,
                &twiddles,
            );
            assert_eq!(actual, expected, "log_n={log_n}, case={case}");
        }
    }
}

#[test]
fn program_is_base_or_interaction_only_and_seals_exact_batches() {
    let admitted = commit(1);
    for role in [TraceTreeRole::Base, TraceTreeRole::Interaction] {
        let direct = DirectRetainedB2nProgram::compile(role, &admitted).unwrap();
        assert_eq!(direct.role(), role);
        assert_eq!(direct.batches().len(), 2);
        assert_eq!(direct.batches()[0].canonical_columns, [0, 1]);
        assert_eq!(direct.batches()[1].canonical_columns, [2]);
        assert!(direct
            .batches()
            .iter()
            .all(|batch| batch.retained_log_size == batch.source_log_size + 1));
    }
    for role in [TraceTreeRole::Preprocessed, TraceTreeRole::Composition] {
        assert_eq!(
            DirectRetainedB2nProgram::compile(role, &admitted),
            Err(DirectRetainedB2nError::UnsupportedRole(role))
        );
    }
    assert_eq!(
        DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &commit(2)),
        Err(DirectRetainedB2nError::UnsupportedBlowup(2))
    );
}

#[test]
fn pointer_tables_exclusively_replace_the_existing_lde_tables() {
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &commit(1)).unwrap();
    let slots = slots(direct.batches().len());
    let required = direct.arena_slot_requirements(&slots).unwrap();
    let expected = slots
        .leaves
        .batches
        .iter()
        .flat_map(|batch| [batch.coefficient_ptrs, batch.output_ptrs])
        .collect::<Vec<_>>();
    assert_eq!(
        required.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        expected
    );

    let mut aliased = slots;
    aliased.leaves.batches[1].coefficient_ptrs = aliased.leaves.batches[0].output_ptrs;
    assert!(matches!(
        direct.arena_slot_requirements(&aliased),
        Err(DirectRetainedB2nError::InvalidAlias { .. })
    ));
}

#[test]
fn both_global_tree_extents_are_preserved_and_reported_without_transposition() {
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &commit(1)).unwrap();
    let inverse_words = direct.twiddle_words * 4;
    let forward_words = direct.twiddle_words * 8;
    let inverse = ArenaSlice::dangling_at_for_test(9, 700, inverse_words);
    let forward = ArenaSlice::dangling_at_for_test(10, 700 + inverse_words, forward_words);
    let admitted_inverse = admit_twiddles(&direct, inverse, inverse.context_token()).unwrap();
    let admitted_forward = admit_twiddles(&direct, forward, forward.context_token()).unwrap();
    assert_eq!(admitted_inverse, u32::try_from(inverse_words).unwrap());
    assert_eq!(admitted_forward, u32::try_from(forward_words).unwrap());
    assert!(inverse_words > direct.twiddle_words);
    assert!(forward_words > inverse_words);

    let batch = &direct.batches()[0];
    let telemetry = PreparedBatch {
        input_pointers: ArenaSlice::dangling_at_for_test(11, 30_000, batch.pointer_words),
        output_pointers: ArenaSlice::dangling_at_for_test(12, 31_000, batch.pointer_words),
        batch_index: batch.batch_index,
        first_column: u32::try_from(batch.canonical_columns[0]).unwrap(),
        source_log_size: batch.source_log_size,
        retained_log_size: batch.retained_log_size,
        columns: u32::try_from(batch.canonical_columns.len()).unwrap(),
    }
    .launch_kind(TraceTreeRole::Base, admitted_inverse, admitted_forward);
    assert_eq!(telemetry.first_column, 0);
    assert_eq!(telemetry.inverse_twiddle_words, admitted_inverse);
    assert_eq!(telemetry.forward_twiddle_words, admitted_forward);
    assert_ne!(
        telemetry.inverse_twiddle_words,
        telemetry.forward_twiddle_words
    );

    let oversized =
        ArenaSlice::dangling_at_for_test(13, 40_000, usize::try_from(u32::MAX).unwrap() + 1);
    assert_eq!(
        admit_twiddles(&direct, oversized, oversized.context_token()),
        Err(DirectRetainedB2nError::SizeOverflow)
    );
}

#[test]
fn cpu_oracle_matches_full_lde_and_detects_one_word_mutation() {
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &commit(1)).unwrap();
    let sources = direct
        .batches()
        .iter()
        .flat_map(|batch| {
            batch.canonical_columns.iter().map(|&canonical| {
                (0..1usize << batch.source_log_size)
                    .map(|row| ((canonical * 97 + row * 31 + 11) as u32) % P)
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let oracle = direct.oracle(&sources).unwrap();
    for (column, retained) in oracle.retained_stage_two_inputs.iter().enumerate() {
        let half = retained.len() / 2;
        assert_ne!(retained[..half], sources[column]);
        assert_eq!(retained[..half], retained[half..]);

        let source_log = sources[column].len().ilog2();
        let expected = CircleEvaluation::<CpuBackend, BaseField, BitReversedOrder>::new(
            CanonicCoset::new(source_log).circle_domain(),
            sources[column]
                .iter()
                .copied()
                .map(BaseField::from_u32_unchecked)
                .collect(),
        )
        .interpolate()
        .evaluate(CanonicCoset::new(source_log + 1).circle_domain())
        .values
        .into_iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
        assert_eq!(oracle.retained_evaluations[column], expected);
    }

    let mut mutated_sources = sources.clone();
    mutated_sources[1][3] = (mutated_sources[1][3] + 1) % P;
    let mutated = direct.oracle(&mutated_sources).unwrap();
    for column in 0..sources.len() {
        if column == 1 {
            assert_ne!(
                mutated.retained_evaluations[column],
                oracle.retained_evaluations[column]
            );
        } else {
            assert_eq!(
                mutated.retained_evaluations[column],
                oracle.retained_evaluations[column]
            );
        }
    }
}

#[test]
fn value_aliases_allow_only_the_same_owner_lower_prefix() {
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &commit(1)).unwrap();
    let mut columns = vec![
        DirectRetainedB2nColumn {
            source_evaluations: ArenaSlice::dangling_at_for_test(1, 100, 8),
            retained_output: ArenaSlice::dangling_at_for_test(1, 100, 16),
        },
        DirectRetainedB2nColumn {
            source_evaluations: ArenaSlice::dangling_at_for_test(2, 200, 8),
            retained_output: ArenaSlice::dangling_at_for_test(3, 300, 16),
        },
        DirectRetainedB2nColumn {
            source_evaluations: ArenaSlice::dangling_at_for_test(4, 400, 16),
            retained_output: ArenaSlice::dangling_at_for_test(5, 500, 32),
        },
    ];
    let admitted = columns.clone();
    let token = columns[0].source_evaluations.context_token();
    let logical = bind_logical_columns(&direct, &columns, token).unwrap();
    let inverse_twiddles = ArenaSlice::dangling_at_for_test(9, 700, 64);
    let forward_twiddles = ArenaSlice::dangling_at_for_test(10, 900, 64);
    validate_value_aliases(&logical, inverse_twiddles, forward_twiddles).unwrap();
    assert!(exact_lower_prefix_alias(logical[0]));

    assert!(matches!(
        validate_value_aliases(&logical, inverse_twiddles, inverse_twiddles),
        Err(DirectRetainedB2nError::InvalidAlias { .. })
    ));

    let overlapping_forward = ArenaSlice::dangling_at_for_test(11, 710, 64);
    assert!(matches!(
        validate_value_aliases(&logical, inverse_twiddles, overlapping_forward),
        Err(DirectRetainedB2nError::InvalidAlias { .. })
    ));

    columns[0].source_evaluations = ArenaSlice::dangling_at_for_test(1, 101, 8);
    let logical = bind_logical_columns(&direct, &columns, token).unwrap();
    assert!(matches!(
        validate_value_aliases(&logical, inverse_twiddles, forward_twiddles),
        Err(DirectRetainedB2nError::InvalidAlias { .. })
    ));

    columns[0].source_evaluations = ArenaSlice::dangling_at_for_test(6, 100, 8);
    let logical = bind_logical_columns(&direct, &columns, token).unwrap();
    assert!(matches!(
        validate_value_aliases(&logical, inverse_twiddles, forward_twiddles),
        Err(DirectRetainedB2nError::InvalidAlias { .. })
    ));

    // Terminal pair ownership writes four-column tranches in place. Distinct
    // canonical outputs must therefore be disjoint even when their Arena IDs
    // differ and only their physical address ranges overlap.
    let mut terminal_alias = admitted;
    terminal_alias[1].retained_output = ArenaSlice::dangling_at_for_test(12, 108, 16);
    let logical = bind_logical_columns(&direct, &terminal_alias, token).unwrap();
    assert!(matches!(
        validate_value_aliases(&logical, inverse_twiddles, forward_twiddles),
        Err(DirectRetainedB2nError::InvalidAlias { .. })
    ));
}
