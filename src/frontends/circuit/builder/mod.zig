//! The circuit builder: a call-order-exact port of `crates/circuits`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), design §3 of
//! `design/starknet-proving-pipeline/recursion/02-design.md`.
//!
//! Invariants every module keeps (each has a test):
//! - variables are numbered in call order; 0, 1, 2 are zero, one and `u`;
//! - constants are interned in first-use order and yielded by
//!   `finalize_constants` in upstream's gate order;
//! - the only gate elisions are index-only (`add` with var 0, `mul` with var 0
//!   or 1); nothing folds values or hash-conses gates;
//! - `Context(QM31)` and `Context(NoValue)` build identical gate lists.

/// `crates/circuits/src/circuit.rs`: gates, `Circuit`, satisfaction check.
pub const circuit = @import("circuit.zig");
/// `crates/circuits/src/ivalue.rs`: the `QM31 | NoValue` value surface.
pub const ivalue = @import("ivalue.zig");
/// `crates/circuits/src/context.rs` and the primitive gates of `ops.rs`.
pub const context = @import("context.zig");
/// `crates/circuits/src/ops.rs`: composite operations.
pub const ops = @import("ops.zig");
/// `crates/circuits/src/wrappers.rs`: M31, U16 and U32 wires.
pub const wrappers = @import("wrappers.zig");
/// `crates/circuits/src/simd.rs`: M31 lanes packed into QM31 wires.
pub const simd = @import("simd.zig");
/// `crates/circuits/src/extract_bits.rs`.
pub const extract_bits = @import("extract_bits.zig");
/// `crates/circuits/src/blake.rs`: Blake2s gates and gadgets.
pub const blake = @import("blake.zig");
/// `select_by_index` of `crates/circuits/src/utils.rs`.
pub const select = @import("select.zig");
/// `crates/circuits/src/finalize_constants.rs`.
pub const finalize_constants = @import("finalize_constants.zig");
/// Upstream `Debug` text of circuits and constants.
pub const debug_format = @import("debug_format.zig");

pub const Var = context.Var;
pub const Circuit = circuit.Circuit;
pub const Context = context.Context;
pub const NoValue = ivalue.NoValue;

test {
    @import("std").testing.refAllDecls(@This());
}
