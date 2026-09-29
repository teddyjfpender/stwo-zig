//! Component sizing and padding of a finalized circuit.
//!
//! Port of the sizing and padding half of `crates/circuit_common/src/finalize.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230); the ZK half is
//! `zk_blinding.zig`. Padding appends real gates through the builder API, so
//! the constants it requests after `finalize` take upstream's path (the zero
//! word of `pad_triple_xor` and `pad_blake_g_gate` is var 0).
//!
//! Padding order is eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate
//! (`pad_to_targets`); `ComponentSizes` keeps the Rust declaration order.

const std = @import("std");
const builder = @import("../builder/mod.zig");

const Error = builder.context.Error;

/// `N_LANES`: the minimum padded component size.
pub const n_lanes = 16;

/// Row counts of the five gate-driven AIR components.
pub const ComponentSizes = struct {
    eq: usize,
    qm31_ops: usize,
    m31_to_u32: usize,
    triple_xor: usize,
    blake_g_gate: usize,

    /// `ComponentSizes::map`.
    pub fn map(self: ComponentSizes, comptime f: fn (usize) usize) ComponentSizes {
        return .{ .eq = f(self.eq), .qm31_ops = f(self.qm31_ops), .m31_to_u32 = f(self.m31_to_u32), .triple_xor = f(self.triple_xor), .blake_g_gate = f(self.blake_g_gate) };
    }

    /// `ComponentSizes::elementwise_max`: the shared target of several circuits.
    pub fn elementwiseMax(self: ComponentSizes, other: ComponentSizes) ComponentSizes {
        return .{
            .eq = @max(self.eq, other.eq),
            .qm31_ops = @max(self.qm31_ops, other.qm31_ops),
            .m31_to_u32 = @max(self.m31_to_u32, other.m31_to_u32),
            .triple_xor = @max(self.triple_xor, other.triple_xor),
            .blake_g_gate = @max(self.blake_g_gate, other.blake_g_gate),
        };
    }

    /// `impl Display`: each size with its rounded-up log2.
    pub fn format(self: ComponentSizes, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print(
            "eq={d:>2} (log: {d}),  qm31_ops={d:>2} (log: {d}), m31_to_u32={d:>2} (log: {d}), " ++
                "triple_xor={d:>2} (log: {d}), blake_g_gate={d:>2} (log: {d})",
            .{
                self.eq,           ceilLog2(self.eq),           self.qm31_ops,   ceilLog2(self.qm31_ops),
                self.m31_to_u32,   ceilLog2(self.m31_to_u32),   self.triple_xor, ceilLog2(self.triple_xor),
                self.blake_g_gate, ceilLog2(self.blake_g_gate),
            },
        );
    }
};

/// `next_power_of_two().ilog2()`.
fn ceilLog2(n: usize) usize {
    return std.math.log2_int(usize, std.math.ceilPowerOfTwoAssert(usize, @max(n, 1)));
}

/// `padded_size`: the next power of two, at least `n_lanes`.
pub fn paddedSize(n_rows: usize) usize {
    return @max(std.math.ceilPowerOfTwoAssert(usize, @max(n_rows, 1)), n_lanes);
}

/// `raw_component_sizes`: the unpadded row count of each component.
pub fn rawComponentSizes(circuit: *const builder.Circuit) ComponentSizes {
    return .{
        .eq = circuit.eq.items.len,
        .qm31_ops = circuit.nQm31OpsRows(),
        .m31_to_u32 = circuit.m31_to_u32.items.len,
        .triple_xor = circuit.triple_xor.items.len,
        .blake_g_gate = circuit.blake_g_gate.items.len,
    };
}

/// `compute_padded_sizes`.
pub fn computePaddedSizes(circuit: *const builder.Circuit) ComponentSizes {
    return rawComponentSizes(circuit).map(paddedSize);
}

/// Failures of padding (upstream asserts).
pub const PadError = Error || error{
    /// `pad_*`: a component already has more rows than its target.
    ComponentExceedsTarget,
    /// Padding requires a finalized context.
    NotFinalized,
};

/// `pad_context`: pads each component to its padded size.
pub fn padContext(comptime V: type, ctx: *builder.Context(V)) PadError!void {
    return padToTargets(V, ctx, computePaddedSizes(&ctx.circuit));
}

/// `pad_to_targets`: appends trivial gates until each component has its
/// target row count, in the order eq, qm31_ops, triple_xor, m31_to_u32,
/// blake_g_gate.
pub fn padToTargets(comptime V: type, ctx: *builder.Context(V), targets: ComponentSizes) PadError!void {
    if (!ctx.finalized) return error.NotFinalized;
    try padEq(V, ctx, targets.eq);
    try padQm31Ops(V, ctx, targets.qm31_ops);
    try padTripleXor(V, ctx, targets.triple_xor);
    try padM31ToU32(V, ctx, targets.m31_to_u32);
    try padBlakeGGate(V, ctx, targets.blake_g_gate);
}

fn rowsToAdd(n_rows: usize, target: usize) error{ComponentExceedsTarget}!usize {
    if (n_rows > target) return error.ComponentExceedsTarget;
    return target - n_rows;
}

/// `0 = 0` rows.
fn padEq(comptime V: type, ctx: *builder.Context(V), target: usize) PadError!void {
    for (0..try rowsToAdd(ctx.circuit.eq.items.len, target)) |_| try ctx.eq(ctx.zero(), ctx.zero());
}

/// `1 + 1` rows (`1` rather than `0` so the add peephole does not elide them).
fn padQm31Ops(comptime V: type, ctx: *builder.Context(V), target: usize) PadError!void {
    for (0..try rowsToAdd(ctx.circuit.nQm31OpsRows(), target)) |_| _ = try ctx.add(ctx.one(), ctx.one());
}

/// `0 ^ 0 ^ 0` rows. The zero word is requested even when no row is added.
fn padTripleXor(comptime V: type, ctx: *builder.Context(V), target: usize) PadError!void {
    const n = try rowsToAdd(ctx.circuit.triple_xor.items.len, target);
    const zero = try builder.wrappers.constU32(V, ctx, 0);
    for (0..n) |_| _ = try builder.blake.tripleXor(V, ctx, zero, zero, zero);
}

/// `m31_to_u32(0)` rows.
fn padM31ToU32(comptime V: type, ctx: *builder.Context(V), target: usize) PadError!void {
    for (0..try rowsToAdd(ctx.circuit.m31_to_u32.items.len, target)) |_| _ = try builder.blake.m31ToU32(V, ctx, ctx.zero());
}

/// `G(0, 0, 0, 0, 0, 0)` rows. The zero word is requested even when no row is added.
fn padBlakeGGate(comptime V: type, ctx: *builder.Context(V), target: usize) PadError!void {
    const n = try rowsToAdd(ctx.circuit.blake_g_gate.items.len, target);
    const zero = try builder.wrappers.constU32(V, ctx, 0);
    for (0..n) |_| _ = try builder.blake.blakeGGate(V, ctx, zero, zero, zero, zero, zero, zero);
}

const QM31 = @import("stwo_core").fields.qm31.QM31;

test "finalize: padded sizes round up to a power of two, at least 16" {
    try std.testing.expectEqual(@as(usize, 16), paddedSize(0));
    try std.testing.expectEqual(@as(usize, 16), paddedSize(16));
    try std.testing.expectEqual(@as(usize, 32), paddedSize(17));
    try std.testing.expectEqual(@as(usize, 1 << 20), paddedSize((1 << 20) - 3));
    var buffer: [256]u8 = undefined;
    const sizes: ComponentSizes = .{ .eq = 3, .qm31_ops = 17, .m31_to_u32 = 16, .triple_xor = 1, .blake_g_gate = 1000 };
    try std.testing.expectEqualStrings(
        "eq= 3 (log: 2),  qm31_ops=17 (log: 5), m31_to_u32=16 (log: 4), triple_xor= 1 (log: 0), blake_g_gate=1000 (log: 10)",
        try std.fmt.bufPrint(&buffer, "{f}", .{sizes}),
    );
    const other: ComponentSizes = .{ .eq = 4, .qm31_ops = 1, .m31_to_u32 = 20, .triple_xor = 0, .blake_g_gate = 1 };
    try std.testing.expectEqual(ComponentSizes{ .eq = 4, .qm31_ops = 17, .m31_to_u32 = 20, .triple_xor = 1, .blake_g_gate = 1000 }, sizes.elementwiseMax(other));
}

test "finalize: pad_context pads every component and keeps the circuit valid" {
    const gpa = std.testing.allocator;
    var ctx = try builder.Context(QM31).init(gpa, 0);
    defer ctx.deinit();
    const x = try builder.wrappers.guessU32(QM31, &ctx, builder.wrappers.u32Value(QM31, 0xDEAD_BEEF));
    _ = try builder.blake.tripleXor(QM31, &ctx, x, x, x);
    _ = try builder.blake.blakeGGate(QM31, &ctx, x, x, x, x, x, x);
    try ctx.eq(x.get(), x.get());
    try std.testing.expectError(error.NotFinalized, padContext(QM31, &ctx));
    try ctx.finalize(false);
    const n_constants = ctx.constants.count();
    const padded = computePaddedSizes(&ctx.circuit);
    // The +1 chain of `finalize_constants` alone adds 255 qm31_ops rows.
    try std.testing.expectEqual(ComponentSizes{ .eq = 16, .qm31_ops = 512, .m31_to_u32 = 16, .triple_xor = 16, .blake_g_gate = 16 }, padded);
    try padContext(QM31, &ctx);
    try std.testing.expectEqual(padded, rawComponentSizes(&ctx.circuit));
    // The zero word is var 0: padding interns no new constant.
    try std.testing.expectEqual(n_constants, ctx.constants.count());
    try std.testing.expectEqual(null, try ctx.circuit.firstYieldViolation(gpa));
    try std.testing.expect(try ctx.isCircuitValid());
}

test "finalize: pad_to_targets rejects a component above its target" {
    const gpa = std.testing.allocator;
    var ctx = try builder.Context(builder.NoValue).init(gpa, 0);
    defer ctx.deinit();
    for (0..3) |_| try ctx.eq(ctx.zero(), ctx.zero());
    try ctx.finalize(false);
    try std.testing.expectError(error.ComponentExceedsTarget, padToTargets(builder.NoValue, &ctx, .{ .eq = 2, .qm31_ops = 64, .m31_to_u32 = 16, .triple_xor = 16, .blake_g_gate = 16 }));
}

test "finalize: QM31 and NoValue padding emit the same gates" {
    const gpa = std.testing.allocator;
    const targets: ComponentSizes = .{ .eq = 32, .qm31_ops = 512, .m31_to_u32 = 16, .triple_xor = 16, .blake_g_gate = 32 };
    var values = try builder.Context(QM31).init(gpa, 0);
    defer values.deinit();
    try values.finalize(false);
    try padToTargets(QM31, &values, targets);
    var topology = try builder.Context(builder.NoValue).init(gpa, 0);
    defer topology.deinit();
    try topology.finalize(false);
    try padToTargets(builder.NoValue, &topology, targets);
    const a = try builder.debug_format.circuitText(gpa, &values.circuit);
    defer gpa.free(a);
    const b = try builder.debug_format.circuitText(gpa, &topology.circuit);
    defer gpa.free(b);
    try std.testing.expectEqualStrings(a, b);
    try std.testing.expect(try values.isCircuitValid());
}
