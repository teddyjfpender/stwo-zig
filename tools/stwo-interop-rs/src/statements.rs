use crate::model::{
    BlakeStatement, PlonkStatement, PoseidonStatement, WideFibonacciStatement, XorLookupElements,
    XorStatement, POSEIDON_COLUMNS, POSEIDON_COLUMNS_PER_REP,
};
use crate::traces::blake_n_columns;
use num_traits::One;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;

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

pub(crate) fn xor_combine(
    elements: XorLookupElements,
    a: SecureField,
    b: SecureField,
    c: SecureField,
) -> SecureField {
    a + elements.alpha * b + elements.alpha.square() * c - elements.z
}

pub(crate) fn mix_xor_statement(channel: &mut Blake2sChannel, statement: XorStatement) {
    channel.mix_u32s(&[statement.log_size, statement.log_step]);
    channel.mix_u64(statement.offset as u64);
    channel.mix_felts(&[statement.claimed_sum]);
}
