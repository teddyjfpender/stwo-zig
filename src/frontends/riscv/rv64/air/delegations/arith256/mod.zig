//! arith256_mod truth (Wire35 program kind 4): r = (a*b + c) mod m, r = 0 when
//! m = 0, admitted by the `ethereum_services_v3` profile (tag 0x0003_0021).
//! One call per row, degree 3, native 2n composition in its own PCS with a
//! local BYTE table. The CPU-side packet bridge is the shared Word16 Wire35
//! bridge (`secp256k1.word16_bridge`, kind `.arith256_mod`).
pub const layout = @import("layout.zig");
pub const native = @import("native.zig");
pub const equations = @import("equations.zig");
pub const trace = @import("trace.zig");
pub const component = @import("component.zig");

test {
    _ = native;
    _ = @import("tests.zig");
}
