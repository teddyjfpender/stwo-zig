//! Component sizing and padding of a finalized circuit: `ComponentSizes`,
//! the padded sizes, the qm31_ops row count and `pad_to_targets`.
//!
//! Port of the sizing and padding half of `crates/circuit_common/src/finalize.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230); the ZK half is
//! `zk_blinding.zig`. `ComponentSizes` is the one size struct of the circuit
//! lane: registry `LogSizes` (interop, M3) maps into it by field name,
//! because the two declare their fields in different orders. Padding appends
//! real gates through the builder API, so the constants it requests after
//! `finalize` take upstream's path (the zero word of `pad_triple_xor` and
//! `pad_blake_g_gate` is var 0).

const std = @import("std");
const builder = @import("../builder/mod.zig");
const component_list = @import("component_list.zig");
const preprocessed = @import("preprocessed.zig");

const Error = builder.context.Error;

/// Row counts of the five gate-driven AIR components. Field order is the
/// Rust declaration order (eq, qm31_ops, m31_to_u32, triple_xor,
/// blake_g_gate); padding runs in `PAD_ORDER` instead.
pub const ComponentSizes = struct {
    eq: usize,
    qm31_ops: usize,
    m31_to_u32: usize,
    triple_xor: usize,
    blake_g_gate: usize,

    pub const Field = std.meta.FieldEnum(ComponentSizes);

    /// `ComponentSizes::map`.
    pub fn map(self: ComponentSizes, comptime f: fn (usize) usize) ComponentSizes {
        var out: ComponentSizes = undefined;
        inline for (std.meta.fields(ComponentSizes)) |field| @field(out, field.name) = f(@field(self, field.name));
        return out;
    }

    /// `ComponentSizes::zip`.
    pub fn zip(self: ComponentSizes, other: ComponentSizes, comptime f: fn (usize, usize) usize) ComponentSizes {
        var out: ComponentSizes = undefined;
        inline for (std.meta.fields(ComponentSizes)) |field|
            @field(out, field.name) = f(@field(self, field.name), @field(other, field.name));
        return out;
    }

    /// `ComponentSizes::elementwise_max`: the shared padding target of
    /// several circuits.
    pub fn elementwiseMax(self: ComponentSizes, other: ComponentSizes) ComponentSizes {
        return self.zip(other, maxUsize);
    }

    /// Sizes from per-component log sizes, looked up by field name.
    pub fn fromLogSizes(log_sizes: anytype) ComponentSizes {
        var out: ComponentSizes = undefined;
        inline for (std.meta.fields(ComponentSizes)) |field|
            @field(out, field.name) = @as(usize, 1) << @intCast(@field(log_sizes, field.name));
        return out;
    }

    /// `impl Display for ComponentSizes`.
    pub fn format(self: ComponentSizes, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print(
            "eq={d:>2} (log: {d}),  qm31_ops={d:>2} (log: {d}), m31_to_u32={d:>2} (log: {d}), " ++
                "triple_xor={d:>2} (log: {d}), blake_g_gate={d:>2} (log: {d})",
            .{
                self.eq,           ceilLog2(self.eq),
                self.qm31_ops,     ceilLog2(self.qm31_ops),
                self.m31_to_u32,   ceilLog2(self.m31_to_u32),
                self.triple_xor,   ceilLog2(self.triple_xor),
                self.blake_g_gate, ceilLog2(self.blake_g_gate),
            },
        );
    }
};

/// `pad_to_targets` order: eq, qm31_ops, triple_xor, m31_to_u32,
/// blake_g_gate. Padding emits gates, so this order fixes var numbering.
pub const PAD_ORDER = [_]ComponentSizes.Field{ .eq, .qm31_ops, .triple_xor, .m31_to_u32, .blake_g_gate };

fn maxUsize(a: usize, b: usize) usize {
    return @max(a, b);
}

fn ceilLog2(n: usize) u32 {
    return std.math.log2_int(usize, std.math.ceilPowerOfTwoAssert(usize, @max(n, 1)));
}

/// `padded_size`: the next power of two, at least `N_LANES`.
pub fn paddedSize(n_rows: usize) usize {
    return @max(std.math.ceilPowerOfTwoAssert(usize, @max(n_rows, 1)), component_list.N_LANES);
}

/// `qm31_ops_n_rows`: binary-op gates plus one row per permutation input and
/// output.
pub fn qm31OpsNRows(circuit: preprocessed.CircuitView) usize {
    return circuit.add.len + circuit.sub.len + circuit.mul.len + circuit.pointwise_mul.len +
        circuit.permutationRows();
}

/// `raw_component_sizes`, over either circuit representation: the
/// preprocessing's `CircuitView` or the builder's `Circuit` (padding reads
/// the live builder circuit).
pub fn rawComponentSizes(circuit: anytype) ComponentSizes {
    if (@TypeOf(circuit) == *const builder.Circuit or @TypeOf(circuit) == *builder.Circuit) return .{
        .eq = circuit.eq.items.len,
        .qm31_ops = circuit.nQm31OpsRows(),
        .m31_to_u32 = circuit.m31_to_u32.items.len,
        .triple_xor = circuit.triple_xor.items.len,
        .blake_g_gate = circuit.blake_g_gate.items.len,
    };
    const view: preprocessed.CircuitView = circuit;
    return .{
        .eq = view.eq.len,
        .qm31_ops = qm31OpsNRows(view),
        .m31_to_u32 = view.m31_to_u32.len,
        .triple_xor = view.triple_xor.len,
        .blake_g_gate = view.blake_g_gate.len,
    };
}

/// `compute_padded_sizes`.
pub fn computePaddedSizes(circuit: anytype) ComponentSizes {
    return rawComponentSizes(circuit).map(paddedSize);
}

test "finalize: padded size rounds up to a power of two of at least N_LANES" {
    try std.testing.expectEqual(@as(usize, 16), paddedSize(0));
    try std.testing.expectEqual(@as(usize, 16), paddedSize(1));
    try std.testing.expectEqual(@as(usize, 16), paddedSize(16));
    try std.testing.expectEqual(@as(usize, 32), paddedSize(17));
    try std.testing.expectEqual(@as(usize, 1 << 21), paddedSize((1 << 20) + 1));
}

test "finalize: ComponentSizes maps by field name and takes elementwise maxima" {
    const a: ComponentSizes = .{ .eq = 1, .qm31_ops = 9, .m31_to_u32 = 3, .triple_xor = 7, .blake_g_gate = 5 };
    const b: ComponentSizes = .{ .eq = 4, .qm31_ops = 2, .m31_to_u32 = 6, .triple_xor = 1, .blake_g_gate = 8 };
    try std.testing.expectEqual(
        ComponentSizes{ .eq = 4, .qm31_ops = 9, .m31_to_u32 = 6, .triple_xor = 7, .blake_g_gate = 8 },
        a.elementwiseMax(b),
    );
    // A registry-style struct with a different field order maps by name.
    const RegistryLogSizes = struct { eq: u32, qm31_ops: u32, m31_to_u32: u32, triple_xor: u32, blake_g_gate: u32 };
    const sizes = ComponentSizes.fromLogSizes(RegistryLogSizes{
        .eq = 20,
        .qm31_ops = 23,
        .m31_to_u32 = 21,
        .triple_xor = 20,
        .blake_g_gate = 23,
    });
    try std.testing.expectEqual(@as(usize, 1 << 21), sizes.m31_to_u32);
    try std.testing.expectEqual(@as(usize, 1 << 20), sizes.triple_xor);

    var buffer: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{ComponentSizes{
        .eq = 3,
        .qm31_ops = 16,
        .m31_to_u32 = 17,
        .triple_xor = 1,
        .blake_g_gate = 100,
    }});
    try std.testing.expectEqualStrings(
        "eq= 3 (log: 2),  qm31_ops=16 (log: 4), m31_to_u32=17 (log: 5), triple_xor= 1 (log: 0), blake_g_gate=100 (log: 7)",
        text,
    );
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
