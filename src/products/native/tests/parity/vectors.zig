//! Rust-generated parity vector test families.

test {
    _ = @import("vectors/fields.zig");
    _ = @import("vectors/pcs_fri.zig");
    _ = @import("vectors/proof_vcs.zig");
    _ = @import("vectors/examples.zig");
}
