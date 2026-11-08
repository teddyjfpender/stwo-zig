//! The paired LogUp secure-column builder now lives in the prover engine
//! (`stwo_prover_engine.air.logup_columns`), shared with the circuit prover.

const logup_columns = @import("stwo_prover_engine").air.logup_columns;

pub const Fraction = logup_columns.Fraction;
pub const Output = logup_columns.Output;
pub const build = logup_columns.build;
