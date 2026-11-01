//! SHA-256 compression truth (Wire35 program kind 3), admitted by the
//! `ethereum_services_v3` profile. One compression per row, degree 3, native
//! 2n composition in its own PCS. The CPU-side packet bridge is the shared
//! Word16 Wire35 bridge (`secp256k1.word16_bridge`, kind `.sha256`).
pub const layout = @import("layout.zig");
pub const native = @import("native.zig");
pub const equations = @import("equations.zig");
pub const trace = @import("trace.zig");
pub const component = @import("component.zig");

test {
    _ = native;
    _ = @import("tests.zig");
}
