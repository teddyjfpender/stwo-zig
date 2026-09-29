//! `stwo_circuit_frontend`: the call-order-exact Zig port of StarkWare's
//! circuit recursion stage (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). See README.md for the map and
//! `design/starknet-proving-pipeline/recursion/02-design.md` for the design.
//!
//! This package must not depend on `stwo_cairo_frontend`; Cairo facts come
//! from the committed compiled-AIR projection.

const std = @import("std");

/// `crates/circuits`: the circuit builder.
pub const builder = @import("builder/mod.zig");
/// `crates/circuit_common`: padding and ZK blinding of finalized circuits.
pub const common = @import("common/mod.zig");

test "api signature: the builder is generic over QM31 and NoValue" {
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const init_values: fn (std.mem.Allocator, usize) builder.context.Error!builder.Context(QM31) = builder.Context(QM31).init;
    const init_topology: fn (std.mem.Allocator, usize) builder.context.Error!builder.Context(builder.NoValue) = builder.Context(builder.NoValue).init;
    const finalize: fn (*builder.Context(QM31), bool) builder.context.FinalizeError!void = builder.Context(QM31).finalize;
    const pad: fn (*builder.Context(QM31), common.finalize.ComponentSizes) common.finalize.PadError!void = struct {
        fn pad(ctx: *builder.Context(QM31), targets: common.finalize.ComponentSizes) common.finalize.PadError!void {
            return common.finalize.padToTargets(QM31, ctx, targets);
        }
    }.pad;
    _ = .{ init_values, init_topology, finalize, pad };
}

test "invariant: vars 0, 1, 2 are zero, one and u, and u is an output" {
    var ctx = try builder.Context(builder.NoValue).init(std.testing.allocator, 0);
    defer ctx.deinit();
    try std.testing.expectEqual(@as(u32, 3), ctx.circuit.n_vars);
    try std.testing.expectEqualSlices(u32, &.{2}, ctx.circuit.output.items);
    try std.testing.expectEqualSlices(builder.Var, &.{ .{ .idx = 0 }, .{ .idx = 1 }, .{ .idx = 2 } }, ctx.constantVars());
}

test {
    std.testing.refAllDecls(@This());
}
