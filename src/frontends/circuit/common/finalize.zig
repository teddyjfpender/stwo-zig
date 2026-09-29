//! Component sizing of a finalized circuit: `ComponentSizes`, the padded
//! sizes and the qm31_ops row count.
//!
//! Ports the host half of `crates/circuit_common/src/finalize.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). `ComponentSizes` is the one
//! size struct of the circuit lane: registry `LogSizes` (interop, M3) maps
//! into it by field name, because the two declare their fields in different
//! orders. The gate-emitting half (`pad_to_targets`, `pad_context`,
//! `add_zk_blinding`) runs through the builder `Context` and lands with it.

const std = @import("std");
const component_list = @import("component_list.zig");
const preprocessed = @import("preprocessed.zig");

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

/// `raw_component_sizes`.
pub fn rawComponentSizes(circuit: preprocessed.CircuitView) ComponentSizes {
    return .{
        .eq = circuit.eq.len,
        .qm31_ops = qm31OpsNRows(circuit),
        .m31_to_u32 = circuit.m31_to_u32.len,
        .triple_xor = circuit.triple_xor.len,
        .blake_g_gate = circuit.blake_g_gate.len,
    };
}

/// `compute_padded_sizes`.
pub fn computePaddedSizes(circuit: preprocessed.CircuitView) ComponentSizes {
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
