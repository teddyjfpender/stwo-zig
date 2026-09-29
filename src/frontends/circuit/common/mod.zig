//! Port of `crates/circuit_common` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230): the parts that drive the
//! builder after `finalize`.

/// Component sizing and padding (`finalize.rs`).
pub const finalize = @import("finalize.zig");
/// ZK blinding rows (`finalize.rs::add_zk_blinding`).
pub const zk_blinding = @import("zk_blinding.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
