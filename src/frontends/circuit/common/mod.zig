//! Port of `crates/circuit_common` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230) plus the shared circuit
//! component list.
pub const component_list = @import("component_list.zig");
pub const component_utils = @import("component_utils.zig");
pub const circuit_hash = @import("circuit_hash.zig");
/// Component sizing and padding (`finalize.rs`).
pub const finalize = @import("finalize.zig");
pub const preprocessed = @import("preprocessed.zig");
pub const sparse_arithmetic = @import("sparse_arithmetic.zig");
pub const direct_arithmetic = @import("direct_arithmetic.zig");
/// ZK blinding rows (`finalize.rs::add_zk_blinding`).
pub const zk_blinding = @import("zk_blinding.zig");
