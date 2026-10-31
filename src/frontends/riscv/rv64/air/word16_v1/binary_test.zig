const std = @import("std");
const E = @import("../evaluation.zig");
const B = @import("binary.zig");
const Ops = @import("operations.zig");
const Decode = @import("../../decode.zig");
const P = @import("binary_lookup.zig");
const Sink = struct {
    values: [B.CONSTRAINTS]E.Q = undefined,
    count: usize = 0,
    pub fn emit(self: *@This(), value: E.Q) void {
        self.values[self.count] = value;
        self.count += 1;
    }
    fn clean(self: *const @This()) bool {
        if (self.count != B.CONSTRAINTS) return false;
        for (self.values) |value| if (!value.isZero()) return false;
        return true;
    }
};

test "Word16 family operation authority keeps immediate and branch semantics explicit" {
    for (std.enums.values(Decode.Opcode)) |opcode| {
        if (Ops.classify(opcode)) |op| {
            const limit: u8 = switch (op.family) {
                .alu => 10,
                .binary => 3,
                .shift => 6,
            };
            try std.testing.expect(op.op_id < limit);
            if (op.branch_predicate) try std.testing.expect(op.family == .alu);
            if (op.use_immediate) try std.testing.expect(!Decode.effects(opcode).reads_rs2);
        }
    }
    try std.testing.expect(Ops.classify(.MUL) == null);
    try std.testing.expect(Ops.classify(.LD) == null);
    try std.testing.expect(Ops.classify(.BEQ).?.branch_predicate);
    try std.testing.expectEqual(Ops.classify(.ADD).?.op_id, Ops.classify(.ADDI).?.op_id);
}

test "Word16 binary byte table obligations bind all limb results and selectors" {
    const words = [_]u64{ 0, 1, 0x7fff8000ffff0000, 0xffffffffffffffff, 0x0123456789abcdef, 0xfedcba9876543210 };
    for (std.enums.values(Ops.Binary)) |op| for (words) |a| for (words) |b| {
        const row = B.witness(op, a, b);
        var sink = Sink{};
        B.emitFor(E.Q, &row, &sink);
        try std.testing.expect(sink.clean());
        for (0..8) |i| {
            const tuple = B.andTupleFor(E.Q, &row, i);
            const av = tuple[0].toM31Array()[0].v;
            const bv = tuple[1].toM31Array()[0].v;
            try std.testing.expect(av < 256 and bv < 256);
            try std.testing.expectEqual(av & bv, tuple[2].toM31Array()[0].v);
        }
        var bad = row;
        bad.payload[12] = bad.payload[12].add(E.Q.one());
        sink = .{};
        B.emitFor(E.Q, &bad, &sink);
        try std.testing.expect(!sink.clean());
        bad = row;
        bad.selectors[0] = E.q(2);
        sink = .{};
        B.emitFor(E.Q, &bad, &sink);
        try std.testing.expect(!sink.clean());
    };
    var padding = B.witness(.and_, 0, 0);
    padding.active = E.Q.zero();
    padding.selectors[0] = E.Q.zero();
    padding.payload[0] = E.Q.zero();
    var sink = Sink{};
    B.emitFor(E.Q, &padding, &sink);
    try std.testing.expect(sink.clean());
    padding.a[0] = E.Q.one();
    sink = .{};
    B.emitFor(E.Q, &padding, &sink);
    try std.testing.expect(!sink.clean());
}

test "Word16 family-local opcode collision cannot cancel global function facts" {
    const Bus = @import("function_bus.zig");
    const p = @import("stwo_core").fields.m31.Modulus;
    try std.testing.expectEqual(@as(u64, p - 1), try Bus.admitPositiveMass(&.{p - 1}));
    try std.testing.expectError(error.Word16MassExceeded, Bus.admitPositiveMass(&.{ p - 1, 1 }));
    try std.testing.expectError(error.Word16MassExceeded, Bus.admitPositiveMass(&.{p}));
    try std.testing.expect(Ops.busIdFor(.alu, 0) != Ops.busIdFor(.binary, 0));
    try std.testing.expect(Ops.busIdFor(.binary, 0) != Ops.busIdFor(.shift, 0));
    var row = B.witness(.and_, 0, 0);
    row.payload[0] = E.q(Ops.busIdFor(.alu, 0));
    var sink = Sink{};
    B.emitFor(E.Q, &row, &sink);
    try std.testing.expect(!sink.clean());
}

test "Word16 binary one authority preserves arbitrary secure sixteen lane residuals" {
    var scalar: [16]B.RowFor(E.Q) = undefined;
    var packed_row: B.RowFor(E.PackedSecure) = undefined;
    var counter: u32 = 1;
    inline for (std.meta.fields(B.RowFor(E.Q))) |field| {
        if (@typeInfo(field.type) == .array) {
            for (0..@typeInfo(field.type).array.len) |i| {
                var values: [16]E.Q = undefined;
                for (&values, 0..) |*value, lane| {
                    value.* = E.Q.fromU32Unchecked(counter, counter + 1, counter + 2, counter + 3);
                    counter += 4;
                    @field(scalar[lane], field.name)[i] = value.*;
                }
                @field(packed_row, field.name)[i] = E.PackedSecure.fromLanes(values);
            }
        } else {
            var values: [16]E.Q = undefined;
            for (&values, 0..) |*value, lane| {
                value.* = E.Q.fromU32Unchecked(counter, counter + 1, counter + 2, counter + 3);
                counter += 4;
                @field(scalar[lane], field.name) = value.*;
            }
            @field(packed_row, field.name) = E.PackedSecure.fromLanes(values);
        }
    }
    var residuals: [B.CONSTRAINTS]E.PackedSecure = undefined;
    var sink = E.SinkFor(E.PackedSecure){ .values = &residuals };
    B.emitFor(E.PackedSecure, &packed_row, &sink);
    try std.testing.expectEqual(B.CONSTRAINTS, sink.count);
    for (0..16) |lane| {
        var reference = Sink{};
        B.emitFor(E.Q, &scalar[lane], &reference);
        for (residuals, reference.values) |actual, expected| try std.testing.expect(actual.lane(lane).eql(expected));
    }
}

fn packFields(comptime F: type, comptime n: usize, scalar: *[16][n]E.Q, counter: *u32) [n]F {
    var result: [n]F = undefined;
    for (0..n) |i| {
        var base: [16]@import("stwo_core").fields.m31.M31 = undefined;
        var secure: [16]E.Q = undefined;
        for (0..16) |lane| {
            const x = counter.*;
            counter.* += 4;
            base[lane] = .fromCanonical(x);
            secure[lane] = if (F == E.PackedBase) E.q(x) else E.Q.fromU32Unchecked(x, x + 1, x + 2, x + 3);
            scalar[lane][i] = secure[lane];
        }
        result[i] = if (F == E.PackedBase) F.fromLanes(base) else F.fromLanes(secure);
    }
    return result;
}
test "Word16 binary complete mixed lookup authority matches scalar OODS and native lanes" {
    const claims = P.Claims{ .and_ = E.Q.fromU32Unchecked(1, 2, 3, 4), .function = E.Q.fromU32Unchecked(5, 6, 7, 8) };
    const ch = P.Challenges{ .and_ = .{ .offset = claims.and_, .coefficients = @splat(claims.function) }, .function = .{ .offset = claims.function, .coefficients = @splat(claims.and_) } };
    inline for (.{ E.PackedBase, E.PackedSecure }) |F| {
        var counter: u32 = 10;
        var main_scalar: [16][P.MAIN]E.Q = undefined;
        var current_scalar: [16][P.INTERACTION]E.Q = undefined;
        var previous_scalar: [16][P.INTERACTION]E.Q = undefined;
        var flags_scalar: [16][2]E.Q = undefined;
        const main = packFields(F, P.MAIN, &main_scalar, &counter);
        const current = packFields(F, P.INTERACTION, &current_scalar, &counter);
        const previous = packFields(F, P.INTERACTION, &previous_scalar, &counter);
        const flags = packFields(F, 2, &flags_scalar, &counter);
        var values: [P.CONSTRAINTS]E.PackedSecure = undefined;
        var sink = E.SinkFor(F){ .values = &values };
        P.emitFor(F, &main, &current, &previous, flags[0], flags[1], claims, ch, &sink);
        try std.testing.expectEqual(P.CONSTRAINTS, sink.count);
        for (0..16) |lane| {
            var reference: [P.CONSTRAINTS]E.Q = undefined;
            var scalar_sink = E.Sink{ .values = &reference };
            P.emitFor(E.Q, &main_scalar[lane], &current_scalar[lane], &previous_scalar[lane], flags_scalar[lane][0], flags_scalar[lane][1], claims, ch, &scalar_sink);
            for (values, reference) |actual, expected| try std.testing.expect(actual.lane(lane).eql(expected));
        }
    }
}
