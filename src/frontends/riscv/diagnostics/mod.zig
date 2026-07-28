//! Proof-independent diagnostic surfaces owned by the RISC-V frontend.

pub const public_values = @import("public_values.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
