//! Immutable V3 truth geometry. One runtime dispatch, original equation authority.
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../roster.zig");
pub fn Sha() type {
    return struct {
        pub const L = A.crypto.sha256.layout;
        pub const N = A.crypto.sha256.native;
        pub const Eq = A.crypto.sha256.equations;
        pub const fixed = L.FIXED;
        pub const batch = 2;
        pub const bytes = 0;
        pub const wires = 4;
        pub const wire_batches = 2;
        pub const byte_batches = 0;
        pub const main_constraints = L.CONSTRAINTS - 2;
        pub const degree = 3;
    };
}
pub fn Arith() type {
    return struct {
        pub const L = A.crypto.arith256.layout;
        pub const N = A.crypto.arith256.native;
        pub const Eq = A.crypto.arith256.equations;
        pub const fixed = L.FIXED;
        pub const batch = 2;
        pub const bytes = L.BYTE_QUERIES;
        pub const wires = L.WIRE_FRACTIONS;
        pub const byte_batches = L.BYTE_BATCHES;
        pub const wire_batches = L.WIRE_BATCHES;
        pub const main_constraints = L.MAIN_CONSTRAINTS;
        pub const degree = 3;
    };
}
pub fn Curve(comptime op: anytype) type {
    return struct {
        pub const L = A.crypto.curves.Layout(op);
        pub const N = A.crypto.curves.Native(op);
        pub const Eq = A.crypto.curves.Equations(op);
        pub const fixed = A.crypto.curves.layout.FIXED;
        pub const batch = L.BATCH;
        pub const bytes = L.BYTE_QUERIES;
        pub const wires = L.WIRE_FRACTIONS;
        pub const byte_batches = L.BYTE_BATCHES;
        pub const wire_batches = L.WIRE_BATCHES;
        pub const main_constraints = L.MAIN_CONSTRAINTS;
        pub const degree = L.BATCH + 1;
    };
}
pub fn visit(truth: R.Truth, ctx: anytype) !void {
    switch (truth) {
        .sha256 => try ctx.call(Sha()),
        .arith256_mod => try ctx.call(Arith()),
        .curve => |t| switch (t.setup.op) {
            inline else => |op| try ctx.call(Curve(op)),
        },
        .secp_row => |t| switch (t.setup.kind) {
            inline else => |op| try ctx.call(Curve(op)),
        },
        else => return error.NotV3Truth,
    }
}
pub fn logSize(truth: R.Truth) !u32 {
    return switch (truth) {
        .sha256 => |t| t.setup.log,
        .arith256_mod => |t| t.setup.log,
        .curve => |t| t.setup.log,
        .secp_row => |t| t.setup.log,
        else => error.NotV3Truth,
    };
}
pub const Shape = struct { fixed: usize, main: usize, inter: usize, constraints: usize, degree: u32, byte_batches: usize, wire_batches: usize };
pub fn shape(truth: R.Truth) !Shape {
    var ctx = struct {
        value: Shape = undefined,
        pub fn call(s: *@This(), comptime T: type) !void {
            s.value = .{ .fixed = T.fixed, .main = T.L.MAIN, .inter = (T.byte_batches + T.wire_batches) * 8, .constraints = T.main_constraints + T.byte_batches + T.wire_batches, .degree = T.degree, .byte_batches = T.byte_batches, .wire_batches = T.wire_batches };
        }
    }{};
    try visit(truth, &ctx);
    return ctx.value;
}
pub fn validate(truth: R.Truth) !void {
    if (truth.count() == 0) return error.EmptyV3Truth;
    const log = try logSize(truth);
    var ctx = struct {
        truth: R.Truth,
        log: u32,
        pub fn call(s: *@This(), comptime T: type) !void {
            try T.L.validateGeometry(s.truth.count(), s.truth.first(), s.log);
        }
    }{ .truth = truth, .log = log };
    try visit(truth, &ctx);
}

pub const Descriptor = struct {
    log_size: u32,
    shape: Shape,
    pub fn widths(s: @This()) [3]usize {
        return .{ s.shape.fixed, s.shape.main, s.shape.inter };
    }
    pub fn nConstraints(s: @This()) usize {
        return s.shape.constraints;
    }
    pub fn maxDegree(s: @This()) u8 {
        return @intCast(s.shape.degree);
    }
    pub fn maxSamples(_: @This()) usize {
        return 2;
    }
};
pub fn descriptor(truth: R.Truth) !Descriptor {
    try validate(truth);
    return .{ .log_size = try logSize(truth), .shape = try shape(truth) };
}
pub fn metadataByteUpperBound(truth: R.Truth) !usize {
    const std = @import("std");
    var ctx = struct {
        calls: usize,
        total: usize = 0,
        pub fn call(s: *@This(), comptime T: type) !void {
            const item = if (T == Sha() or T == Arith()) @sizeOf(T.N.Input) else @sizeOf(T.N.Packet);
            s.total = try std.math.add(usize, try std.math.mul(usize, s.calls, item), @sizeOf(R.TruthSource) + (if (T.bytes == 0) @as(usize, 0) else 256 * @sizeOf(u64)));
        }
    }{ .calls = truth.count() };
    try visit(truth, &ctx);
    return ctx.total;
}
pub fn descriptorForDeclaration(d: @import("../wire.zig").TruthDeclaration) !Descriptor {
    if (d.logs[1] != 0) return error.NotV3Truth;
    if (d.calls == 0) return error.EmptyV3Truth;
    const max_log: u32 = switch (d.family) {
        .sha256 => @import("../../sha256/roster.zig").MAX_LOG,
        .arith256_mod => @import("../../arith256/roster.zig").MAX_LOG,
        .add, .double => @import("../../secp/row_roster.zig").MAX_LOG,
        .keccak => return error.NotV3Truth,
        else => @import("../../curves/roster.zig").MAX_LOG,
    };
    if (d.logs[0] > max_log) return error.V3TruthShapeExceeded;
    var ctx = struct {
        log: u32,
        calls: u32,
        first: u32,
        value: Descriptor = undefined,
        pub fn call(s: *@This(), comptime T: type) !void {
            try T.L.validateGeometry(s.calls, s.first, s.log);
            s.value = .{ .log_size = s.log, .shape = .{ .fixed = T.fixed, .main = T.L.MAIN, .inter = 8 * (T.byte_batches + T.wire_batches), .constraints = T.main_constraints + T.byte_batches + T.wire_batches, .degree = T.degree, .byte_batches = T.byte_batches, .wire_batches = T.wire_batches } };
        }
    }{ .log = d.logs[0], .calls = d.calls, .first = d.first_id };
    switch (d.family) {
        .sha256 => try ctx.call(Sha()),
        .arith256_mod => try ctx.call(Arith()),
        .add => try ctx.call(Curve(A.crypto.curves.spec.SecpKind.add)),
        .double => try ctx.call(Curve(A.crypto.curves.spec.SecpKind.double)),
        .keccak => return error.NotV3Truth,
        inline else => |f| try ctx.call(Curve(@as(A.crypto.curves.Op, @enumFromInt(@intFromEnum(f))))),
    }
    return ctx.value;
}
pub const LookupCounts = struct { byte_unit_consumers: u64, byte_provider_support: u64, byte_denominator_slots: u64, wire_denominator_slots: u64, wire_fractions_per_row: usize, byte_queries_per_row: usize };
pub fn lookupCountsForDeclaration(d: @import("../wire.zig").TruthDeclaration) !LookupCounts {
    const std = @import("std");
    _ = try descriptorForDeclaration(d);
    var ctx = struct {
        bytes: usize = 0,
        wires: usize = 0,
        pub fn call(s: *@This(), comptime T: type) !void {
            s.bytes = T.bytes;
            s.wires = T.wires;
        }
    }{};
    switch (d.family) {
        .sha256 => try ctx.call(Sha()),
        .arith256_mod => try ctx.call(Arith()),
        .add => try ctx.call(Curve(A.crypto.curves.spec.SecpKind.add)),
        .double => try ctx.call(Curve(A.crypto.curves.spec.SecpKind.double)),
        .keccak => return error.NotV3Truth,
        inline else => |f| try ctx.call(Curve(@as(A.crypto.curves.Op, @enumFromInt(@intFromEnum(f))))),
    }
    const n = @as(u64, 1) << @intCast(d.logs[0]);
    return .{ .byte_unit_consumers = try std.math.mul(u64, n, ctx.bytes), .byte_provider_support = if (ctx.bytes == 0) 0 else 256, .byte_denominator_slots = if (ctx.bytes == 0) 0 else try std.math.mul(u64, n, ctx.bytes + 1), .wire_denominator_slots = try std.math.mul(u64, n, ctx.wires), .wire_fractions_per_row = ctx.wires, .byte_queries_per_row = ctx.bytes };
}
