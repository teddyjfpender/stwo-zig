//! Admitted `ethereum_services_v3` curve and field truths (Wire35 program
//! kinds 5..11): BN254 affine G1 add/double and Fp2 multiply, BLS12-381 Fp2
//! Montgomery multiply, the 384-bit Montgomery product (blst's mul_mont_384)
//! and BLS12-381 affine G1 add/double on Montgomery residues. One call per row,
//! degree 3, native 2n composition in its own PCS with a local BYTE table. The
//! CPU-side packet bridge is the shared Word16 Wire35 bridge
//! (`secp256k1.word16_bridge`, kinds 5..11).
pub const spec = @import("spec.zig");
pub const layout = @import("layout.zig");
pub const native = @import("native.zig");
pub const equations = @import("equations.zig");
pub const trace = @import("trace.zig");
pub const component = @import("component.zig");
pub const Op = spec.Op;
pub fn Layout(comptime op: anytype) type {
    return layout.Layout(op);
}
pub fn Native(comptime op: anytype) type {
    return native.Native(op);
}
pub fn Trace(comptime op: anytype) type {
    return trace.Trace(op);
}
pub fn Component(comptime op: anytype) type {
    return component.Component(op);
}
pub fn Equations(comptime op: anytype) type {
    return equations.Equations(op);
}

test {
    _ = @import("tests.zig");
    _ = @import("secp_tests.zig");
}
