use stwo::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasherGeneric};

use super::*;
use crate::backend::progressive_commit::{
    full_lifting_leaf_oracle, lifted_column_index, progressive_leaf_oracle,
    ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry, ProgressiveCommitPlan,
};

fn base_program(logs: &[u32], lifting: u32) -> CommitProgram {
    CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: lifting,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: lifting,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: logs.to_vec(),
                retain_evaluations: true,
            }],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap()
}

fn compact_program(logs: &[u32], lifting: u32) -> CompactDomainProgram {
    let base = base_program(logs, lifting);
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    CompactDomainProgram::compile(&base, &domain).unwrap()
}

#[test]
fn exact_sn1_capacity_cut_is_two_gib_with_qualified_shared_scratch() {
    let base = base_program(&[3, 4], 25);
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    let comparison = compact.comparison();
    assert_eq!(comparison.current_state_slab_words, 805_306_416);
    assert_eq!(comparison.replacement_state_slab_words, 268_435_504);
    assert_eq!(comparison.state_slab_words_saved, 536_870_912);
    assert_eq!(comparison.state_slab_words_saved * 4, 2_147_483_648);
    assert_eq!(
        compact.slab_words(),
        comparison.replacement_state_slab_words
    );
}

#[test]
fn compression_calls_and_merkle_suffix_are_identical_while_traffic_falls() {
    let logs = [vec![3; 17], vec![4; 16], vec![5; 1]].concat();
    let base = base_program(&logs, 6);
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    let comparison = compact.comparison();
    assert_eq!(
        comparison.replacement_leaf_compressions,
        comparison.current_leaf_compressions
    );
    assert_eq!(
        comparison.replacement_state_api_calls,
        comparison.current_state_api_calls
    );
    assert!(
        comparison.replacement_leaf_traffic.owned_read_bytes
            < comparison.current_leaf_traffic.owned_read_bytes
    );
    assert!(
        comparison.replacement_leaf_traffic.owned_write_bytes
            < comparison.current_leaf_traffic.owned_write_bytes
    );
    assert!(
        comparison.replacement_leaf_traffic.kernel_launches
            <= comparison.current_leaf_traffic.kernel_launches
    );
    assert!(
        comparison.replacement_leaf_traffic.device_copies
            <= comparison.current_leaf_traffic.device_copies
    );
    assert_eq!(compact.merkle_suffix(), domain.merkle_suffix());
}

#[test]
fn expansion_copies_h_only_and_accounts_asymmetric_domains_exactly() {
    let compact = compact_program(&[3, 4], 6);
    let expansion = compact
        .steps()
        .iter()
        .find(|step| {
            matches!(
                step.operation,
                CompactDomainOperation::StateExpandInPlace {
                    from_log_size: 4,
                    to_log_size: 5,
                    ..
                }
            )
        })
        .unwrap();
    assert_eq!(expansion.traffic.owned_read_bytes, (16 + 2) * 32);
    assert_eq!(expansion.traffic.owned_write_bytes, (32 + 2) * 32);
    assert_eq!(expansion.traffic.device_copies, 1);
}

#[test]
fn exact_lazy_tail_including_sixteen_words_is_reconstructed() {
    for prefix in [1u32, 15, 16, 17, 31, 32, 33] {
        let mut logs = vec![3; prefix as usize];
        logs.push(4);
        let compact = compact_program(&logs, 6);
        let absorbs = compact
            .steps()
            .iter()
            .filter_map(|step| match step.operation {
                CompactDomainOperation::AbsorbDomainBatch {
                    reconstructed_tail, ..
                } => Some(reconstructed_tail),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(absorbs.len(), 2);
        assert_eq!(absorbs[0], None);
        assert_eq!(
            absorbs[1],
            Some(CompactDomainTail {
                first_column: prefix - ((prefix - 1) % 16 + 1),
                columns: (prefix - 1) % 16 + 1,
            })
        );
    }
    let sixteen = compact_program(&[3; 16], 6);
    let finalize = sixteen
        .steps()
        .iter()
        .find_map(|step| match step.operation {
            CompactDomainOperation::FinalizeInPlace {
                reconstructed_tail, ..
            } => Some(reconstructed_tail),
            _ => None,
        })
        .unwrap();
    assert_eq!(finalize.columns, 16);
    assert_eq!(finalize.first_column, 0);
}

#[test]
fn abstract_h8_tail_reconstruction_matches_progressive_and_full_lifting() {
    for logs in [
        vec![3],
        [vec![3; 15], vec![4; 2]].concat(),
        [vec![3; 16], vec![4; 1], vec![5; 3]].concat(),
        [vec![3; 17], vec![4; 16], vec![5; 1]].concat(),
        [vec![3; 31], vec![4; 2], vec![5; 1]].concat(),
    ] {
        let base = base_program(&logs, 6);
        let plan = &base.requirements().leaves.plan;
        let evaluations = evaluations(plan, logs.len() as u32 ^ 0x9e37_79b9);
        let compact = compact_leaf_oracle(plan, &evaluations);
        assert_eq!(
            compact,
            progressive_leaf_oracle(plan, &evaluations).unwrap()
        );
        assert_eq!(
            compact,
            full_lifting_leaf_oracle(plan, &evaluations).unwrap()
        );

        let mut mutated = evaluations.clone();
        let last = mutated.len() - 1;
        let row = mutated[last].len() - 1;
        mutated[last][row] ^= 0xa5a5_5a5a;
        let changed = compact_leaf_oracle(plan, &mutated);
        assert_ne!(compact, changed);
        assert_eq!(changed, progressive_leaf_oracle(plan, &mutated).unwrap());
        assert_eq!(changed, full_lifting_leaf_oracle(plan, &mutated).unwrap());
    }
}

#[test]
fn lifted_tail_mapping_composes_for_every_small_domain_chain() {
    for target_log in 1..=10 {
        for middle_log in 1..=target_log {
            for source_log in 1..=middle_log {
                for row in 0..1usize << target_log {
                    let through_middle = lifted_column_index(
                        lifted_column_index(row, middle_log, target_log),
                        source_log,
                        middle_log,
                    );
                    assert_eq!(
                        through_middle,
                        lifted_column_index(row, source_log, target_log),
                        "source={source_log} middle={middle_log} target={target_log} row={row}"
                    );
                }
            }
        }
    }
}

#[test]
fn stale_or_mutated_compact_program_is_rejected() {
    let base = base_program(&[3; 17], 6);
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let mut compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    compact.steps[1].traffic.owned_read_bytes += 4;
    assert_eq!(
        compact.validate_against(&base, &domain),
        Err(CompactDomainProgramError::NonCanonicalProgram)
    );
}

#[derive(Clone)]
struct AbstractH8State {
    /// An abstract stand-in for h[8]: only complete non-final blocks survive.
    /// Tests keep their words so the exact canonical stream remains observable.
    compressed_prefix: Vec<u32>,
}

fn compact_leaf_oracle(plan: &ProgressiveCommitPlan, evaluations: &[Vec<u32>]) -> Vec<Blake2sHash> {
    let first_log = plan.columns[0].evaluation_log_size;
    let mut states = vec![
        AbstractH8State {
            compressed_prefix: Vec::new()
        };
        1 << first_log
    ];
    let mut current_log = first_log;
    let mut absorbed = 0usize;
    for batch in &plan.lde_batches {
        if batch.evaluation_log_size > current_log {
            states = (0..1usize << batch.evaluation_log_size)
                .map(|row| {
                    states[lifted_column_index(row, current_log, batch.evaluation_log_size)].clone()
                })
                .collect();
            current_log = batch.evaluation_log_size;
        }
        let pending = pending_words(absorbed);
        for (row, state) in states.iter_mut().enumerate() {
            let mut stream = core::mem::take(&mut state.compressed_prefix);
            for column in absorbed - pending..absorbed {
                stream.push(value_at(evaluations, plan, column, row, current_log));
            }
            for &column in &batch.columns {
                stream.push(value_at(evaluations, plan, column, row, current_log));
            }
            let total = absorbed + batch.columns.len();
            stream.truncate(total - pending_words(total));
            assert_eq!(stream.len() % 16, 0);
            state.compressed_prefix = stream;
        }
        absorbed += batch.columns.len();
    }
    if current_log < plan.geometry.lifting_log_size {
        states = (0..1usize << plan.geometry.lifting_log_size)
            .map(|row| {
                states[lifted_column_index(row, current_log, plan.geometry.lifting_log_size)]
                    .clone()
            })
            .collect();
        current_log = plan.geometry.lifting_log_size;
    }
    let pending = pending_words(absorbed);
    states
        .into_iter()
        .enumerate()
        .map(|(row, mut state)| {
            for column in absorbed - pending..absorbed {
                state
                    .compressed_prefix
                    .push(value_at(evaluations, plan, column, row, current_log));
            }
            assert_eq!(state.compressed_prefix.len(), absorbed);
            let mut hasher = Blake2sHasherGeneric::<false>::default();
            for word in state.compressed_prefix {
                hasher.update(&word.to_le_bytes());
            }
            hasher.finalize()
        })
        .collect()
}

fn value_at(
    evaluations: &[Vec<u32>],
    plan: &ProgressiveCommitPlan,
    column: usize,
    row: usize,
    target_log: u32,
) -> u32 {
    let source_log = plan.columns[column].evaluation_log_size;
    evaluations[column][lifted_column_index(row, source_log, target_log)]
}

fn pending_words(columns: usize) -> usize {
    if columns == 0 {
        0
    } else {
        (columns - 1) % 16 + 1
    }
}

fn evaluations(plan: &ProgressiveCommitPlan, salt: u32) -> Vec<Vec<u32>> {
    plan.columns
        .iter()
        .map(|column| {
            (0..1usize << column.evaluation_log_size)
                .map(|row| {
                    salt.wrapping_add(104_729 * column.canonical_index as u32)
                        .wrapping_add(7_919 * row as u32)
                })
                .collect()
        })
        .collect()
}
