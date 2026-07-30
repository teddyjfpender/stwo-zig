use crate::model::{
    BlakeStatement, PlonkStatement, PoseidonStatement, StateMachineElements, StateMachineStatement,
    WideFibonacciStatement, XorStatement, POSEIDON_COLUMNS, POSEIDON_COLUMNS_PER_REP,
};
use crate::traces::{blake_n_columns, checked_pow2};
use anyhow::{bail, Result};
use num_traits::{One, Zero};
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;

pub(crate) fn state_machine_combine(
    elements: StateMachineElements,
    state: [M31; 2],
) -> SecureField {
    SecureField::from(state[0]) + elements.alpha * SecureField::from(state[1]) - elements.z
}

pub(crate) fn transition_states(
    log_n_rows: u32,
    initial_state: [M31; 2],
) -> Result<([M31; 2], [M31; 2])> {
    if log_n_rows == 0 || log_n_rows >= 31 {
        bail!("invalid log_n_rows");
    }
    let mut intermediate = initial_state;
    intermediate[0] += M31::from_u32_unchecked(1 << log_n_rows);

    let mut final_state = intermediate;
    final_state[1] += M31::from_u32_unchecked(1 << (log_n_rows - 1));

    Ok((intermediate, final_state))
}

pub(crate) fn claimed_sum_telescoping(
    log_size: u32,
    initial_state: [M31; 2],
    inc_index: usize,
    elements: StateMachineElements,
) -> Result<SecureField> {
    if inc_index >= 2 {
        bail!("invalid inc_index");
    }
    let n = checked_pow2(log_size)?;

    let first = state_machine_combine(elements, initial_state);

    let mut last_state = initial_state;
    last_state[inc_index] += M31::from(n);
    let last = state_machine_combine(elements, last_state);

    if first.is_zero() || last.is_zero() {
        bail!("degenerate denominator");
    }

    Ok(first.inverse() - last.inverse())
}

pub(crate) fn prepare_state_machine_statement(
    log_n_rows: u32,
    initial_state: [M31; 2],
    elements: StateMachineElements,
) -> Result<StateMachineStatement> {
    let (intermediate, final_state) = transition_states(log_n_rows, initial_state)?;
    let x_axis_claimed_sum = claimed_sum_telescoping(log_n_rows, initial_state, 0, elements)?;
    let y_axis_claimed_sum = claimed_sum_telescoping(log_n_rows - 1, intermediate, 1, elements)?;

    Ok(StateMachineStatement {
        public_input: [initial_state, final_state],
        stmt0_n: log_n_rows,
        stmt0_m: log_n_rows - 1,
        stmt1_x_axis_claimed_sum: x_axis_claimed_sum,
        stmt1_y_axis_claimed_sum: y_axis_claimed_sum,
    })
}

pub(crate) fn verify_state_machine_statement(
    statement: StateMachineStatement,
    elements: StateMachineElements,
) -> Result<()> {
    let initial_comb = state_machine_combine(elements, statement.public_input[0]);
    let final_comb = state_machine_combine(elements, statement.public_input[1]);
    if initial_comb.is_zero() || final_comb.is_zero() {
        bail!("degenerate denominator");
    }

    let lhs = (statement.stmt1_x_axis_claimed_sum + statement.stmt1_y_axis_claimed_sum)
        * initial_comb
        * final_comb;
    let rhs = final_comb - initial_comb;
    if lhs != rhs {
        bail!("state_machine statement not satisfied");
    }
    Ok(())
}

pub(crate) fn mix_state_machine_stmt0(channel: &mut Blake2sChannel, n: u32, m: u32) {
    channel.mix_u32s(&[n, m]);
}

pub(crate) fn mix_state_machine_public_input(
    channel: &mut Blake2sChannel,
    public_input: &[[M31; 2]; 2],
) {
    channel.mix_u32s(&[
        public_input[0][0].0,
        public_input[0][1].0,
        public_input[1][0].0,
        public_input[1][1].0,
    ]);
}

pub(crate) fn mix_state_machine_stmt1(
    channel: &mut Blake2sChannel,
    x_claim: SecureField,
    y_claim: SecureField,
) {
    channel.mix_felts(&[x_claim, y_claim]);
}

pub(crate) fn mix_wide_fibonacci_statement(
    channel: &mut Blake2sChannel,
    statement: WideFibonacciStatement,
) {
    channel.mix_u32s(&[statement.log_n_rows, statement.sequence_len]);
}

pub(crate) fn plonk_composition_eval(statement: PlonkStatement) -> SecureField {
    SecureField::from_m31(
        M31::from(statement.log_n_rows),
        M31::from(4u32),
        M31::from(1u32),
        M31::one(),
    )
}

pub(crate) fn mix_plonk_statement(channel: &mut Blake2sChannel, statement: PlonkStatement) {
    channel.mix_u32s(&[statement.log_n_rows]);
}

pub(crate) fn poseidon_composition_eval(statement: PoseidonStatement) -> SecureField {
    SecureField::from_m31(
        M31::from(statement.log_n_instances),
        M31::from(POSEIDON_COLUMNS_PER_REP as u32),
        M31::from(POSEIDON_COLUMNS as u32),
        M31::one(),
    )
}

pub(crate) fn mix_poseidon_statement(channel: &mut Blake2sChannel, statement: PoseidonStatement) {
    channel.mix_u32s(&[statement.log_n_instances]);
}

pub(crate) fn blake_composition_eval(statement: BlakeStatement) -> SecureField {
    SecureField::from_m31(
        M31::from(statement.log_n_rows),
        M31::from(statement.n_rounds),
        M31::from(blake_n_columns(statement).unwrap_or(0) as u32),
        M31::one(),
    )
}

pub(crate) fn mix_blake_statement(channel: &mut Blake2sChannel, statement: BlakeStatement) {
    channel.mix_u32s(&[statement.log_n_rows, statement.n_rounds]);
}

pub(crate) fn xor_composition_eval(statement: XorStatement) -> SecureField {
    SecureField::from_m31(
        M31::from(statement.log_size),
        M31::from(statement.log_step),
        M31::from(statement.offset),
        M31::one(),
    )
}

pub(crate) fn mix_xor_statement(channel: &mut Blake2sChannel, statement: XorStatement) {
    channel.mix_u32s(&[statement.log_size, statement.log_step]);
    channel.mix_u64(statement.offset as u64);
}
