use super::*;
use crate::backend::exec_context::ArenaSlice;
use crate::backend::prepared_decommit::TraceTreeRole;
use crate::backend::prepared_progressive_commit::direct_terminal_expand_absorb_binding::validate_slab;
use crate::backend::progressive_commit::ProgressiveCommitGroupGeometry;
use crate::backend::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;

fn programs(
    logs: &[u32],
    lifting_log_size: u32,
) -> (
    CommitProgram,
    DomainCooperativeProgram,
    CompactDomainProgram,
    FusedCompactDomainProgram,
    DirectRetainedB2nProgram,
    DirectCompactTerminalProgram,
) {
    let base = CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        },
        ProgressiveCommitGeometry {
            lifting_log_size,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: logs.to_vec(),
                retain_evaluations: true,
            }],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    let fused = FusedCompactDomainProgram::compile(&base, &domain, &compact).unwrap();
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &base).unwrap();
    let terminal = DirectCompactTerminalProgram::compile(&compact, &direct).unwrap();
    (base, domain, compact, fused, direct, terminal)
}

fn compile(logs: &[u32], lifting: u32) -> DirectTerminalExpandAbsorbProgram {
    let (base, domain, compact, fused, direct, terminal) = programs(logs, lifting);
    DirectTerminalExpandAbsorbProgram::compile(&base, &domain, &compact, &fused, &direct, &terminal)
        .unwrap()
}

#[test]
fn materialized_rise_toggles_banks_while_fixed16_rise_stays_in_place() {
    let logs = [vec![3; 1], vec![12; 16], vec![13; 1]].concat();
    let program = compile(&logs, 14);
    assert_eq!(program.receipt().materialized_batches, 2);
    assert_eq!(program.receipt().fixed16_batches, 1);
    assert_eq!(program.receipt().fused_materialized_rises, 1);
    assert_eq!(program.receipt().fixed16_rises, 1);

    let batches = program
        .operations()
        .iter()
        .filter_map(|operation| match operation {
            DirectTerminalExpandAbsorbOperation::Batch { transition, .. } => Some(*transition),
            _ => None,
        })
        .collect::<Vec<_>>();
    let DirectTerminalExpandAbsorbTransition::None { state: initial } = batches[0] else {
        panic!("initial batch");
    };
    let DirectTerminalExpandAbsorbTransition::Fixed16InPlace { state: fixed, .. } = batches[1]
    else {
        panic!("fixed16 rise");
    };
    let DirectTerminalExpandAbsorbTransition::Materialized {
        source_state,
        destination_state,
        ..
    } = batches[2]
    else {
        panic!("materialized rise");
    };
    assert_eq!(initial.offset_words, program.receipt().state_bank_words);
    assert_eq!(fixed.offset_words, initial.offset_words);
    assert_eq!(source_state.offset_words, initial.offset_words);
    assert_eq!(destination_state.offset_words, 0);
}

#[test]
fn materialized_then_fixed16_preserves_final_zero_placement() {
    let logs = [vec![3; 1], vec![4; 1], vec![12; 16]].concat();
    let program = compile(&logs, 13);
    assert_eq!(program.receipt().fused_materialized_rises, 1);
    assert_eq!(program.receipt().fixed16_rises, 1);
    let finalize = program.operations().last().copied().unwrap();
    let DirectTerminalExpandAbsorbOperation::FinalizeInPlace { state, .. } = finalize else {
        panic!("finalize");
    };
    assert_eq!(state.offset_words, 0);
}

#[test]
fn even_materialized_rises_start_and_finish_at_zero_without_copy() {
    let program = compile(&[3, 4, 5], 6);
    assert_eq!(program.receipt().fused_materialized_rises, 2);
    assert_eq!(program.receipt().fixed16_rises, 0);
    assert_eq!(program.receipt().device_copies_removed, 2);
    let first = program.operations()[0];
    let DirectTerminalExpandAbsorbOperation::Batch {
        transition: DirectTerminalExpandAbsorbTransition::None { state },
        ..
    } = first
    else {
        panic!("initial state");
    };
    assert_eq!(state.offset_words, 0);
    let DirectTerminalExpandAbsorbOperation::FinalizeInPlace { state, .. } =
        *program.operations().last().unwrap()
    else {
        panic!("final state");
    };
    assert_eq!(state.offset_words, 0);
}

#[test]
fn validation_rejects_cross_program_identity() {
    let (base, domain, compact, fused, direct, terminal) = programs(&[3, 4, 5], 6);
    let program = DirectTerminalExpandAbsorbProgram::compile(
        &base, &domain, &compact, &fused, &direct, &terminal,
    )
    .unwrap();
    let (other_base, other_domain, other_compact, other_fused, other_direct, other_terminal) =
        programs(&[3, 4, 6], 7);
    assert_eq!(
        program.validate_against(
            &other_base,
            &other_domain,
            &other_compact,
            &other_fused,
            &other_direct,
            &other_terminal,
        ),
        Err(DirectTerminalExpandAbsorbError::ProgramIdentity)
    );
}

#[test]
fn binding_rejects_a_compact_sized_successor_slab() {
    let (base, domain, compact, fused, direct, terminal) = programs(&[3, 4, 5], 6);
    let program = DirectTerminalExpandAbsorbProgram::compile(
        &base, &domain, &compact, &fused, &direct, &terminal,
    )
    .unwrap();
    let qualified = program.receipt().qualified_slab_capacity_words;
    assert_eq!(qualified, domain.slab_words());
    assert!(qualified > compact.slab_words());

    let slab = ArenaSlice::dangling_for_test(1, qualified);
    let leaves = slab
        .checked_subslice(0, base.requirements().merkle.leaf_words)
        .unwrap();
    let scratch = slab
        .checked_subslice(
            qualified - PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
            PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
        )
        .unwrap();
    validate_slab(&program, &domain, slab, leaves, scratch).unwrap();

    let compact_slab = ArenaSlice::dangling_for_test(1, compact.slab_words());
    let compact_leaves = compact_slab
        .checked_subslice(0, base.requirements().merkle.leaf_words)
        .unwrap();
    let compact_scratch = compact_slab
        .checked_subslice(
            compact.slab_words() - PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
            PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
        )
        .unwrap();
    assert_eq!(
        validate_slab(
            &program,
            &domain,
            compact_slab,
            compact_leaves,
            compact_scratch,
        ),
        Err(DirectCompactDomainBindingError::ProgramIdentity)
    );
}
