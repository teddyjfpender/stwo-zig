//! Compatibility exports for shared recursion frame preparation.
const shared = @import("stwo_riscv_frontend").recursion.transcript_frame_rows_v1;
pub const Step = shared.Step;
pub const callRow = shared.callRow;
pub const binding = shared.binding;
pub const state = shared.state;
pub const word = shared.word;
pub const providerCall = shared.providerCall;
pub const NonceRow = shared.NonceRow;
pub const nonceRows = shared.nonceRows;
