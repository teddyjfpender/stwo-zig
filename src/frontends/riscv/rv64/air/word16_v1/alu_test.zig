const std = @import("std");
const E = @import("../evaluation.zig");
const A = @import("alu.zig");
const Ops = @import("operations.zig");
const P = @import("alu_lookup.zig");
const Sink = struct {
    count: usize = 0,
    nonzero: bool = false,
    pub fn emit(self: *@This(), value: E.Q) void {
        self.count += 1;
        self.nonzero = self.nonzero or !value.isZero();
    }
};
test "Word16 ALU carry bounds signed comparison word extension and output binding" {
    const words = [_]u64{ 0, 1, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff, 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff, 0x0123456789abcdef };
    for (std.enums.values(Ops.Alu)) |op| for (words) |a| for (words) |b| {
        const r = try A.witness(op, a, b);
        var sink = Sink{};
        A.emitFor(E.Q, &r, &sink);
        try std.testing.expectEqual(A.CONSTRAINTS, sink.count);
        try std.testing.expect(!sink.nonzero);
        for (0..A.RANGE_QUERIES) |i| try std.testing.expect(A.rangeValueFor(E.Q, &r, i).toM31Array()[0].v < 65536);
        var forged = r;
        forged.payload[9] = forged.payload[9].add(E.Q.one());
        sink = .{};
        A.emitFor(E.Q, &forged, &sink);
        try std.testing.expect(sink.nonzero);
        forged = r;
        forged.carry[0] = E.q(2);
        sink = .{};
        A.emitFor(E.Q, &forged, &sink);
        try std.testing.expect(sink.nonzero);
    };
}
test "Word16 ALU sign ambiguity fails the explicit range obligation" {
    var r = try A.witness(.slt, 0, 1);
    // Keep the field sign decomposition valid while claiming that 0 has sign1.
    r.sign[0] = E.Q.one();
    r.low[0] = E.q(32768).neg();
    try std.testing.expect(A.rangeValueFor(E.Q, &r, 16).toM31Array()[0].v >= 65536);
}

test "Word16 staged signed predicate bounds every local polynomial by degree three" {
    var samples: [5][A.CONSTRAINTS]E.Q = undefined;
    var genuine_cubic = false;
    for (0..5) |t| {
        var row: A.RowFor(E.Q) = undefined;
        var counter: u32 = 1;
        const x = E.q(@intCast(t));
        inline for (std.meta.fields(A.RowFor(E.Q))) |field| {
            if (@typeInfo(field.type) == .array) {
                for (0..@typeInfo(field.type).array.len) |i| {
                    @field(row, field.name)[i] = E.Q.fromU32Unchecked(counter, counter + 1, counter + 2, counter + 3).add(x.mul(E.Q.fromU32Unchecked(counter + 4, counter + 5, counter + 6, counter + 7)));
                    counter += 8;
                }
            } else {
                @field(row, field.name) = E.Q.fromU32Unchecked(counter, counter + 1, counter + 2, counter + 3).add(x.mul(E.Q.fromU32Unchecked(counter + 4, counter + 5, counter + 6, counter + 7)));
                counter += 8;
            }
        }
        var sink = E.Sink{ .values = &samples[t] };
        A.emitFor(E.Q, &row, &sink);
        try std.testing.expectEqual(A.CONSTRAINTS, sink.count);
    }
    for (0..A.CONSTRAINTS) |c| {
        var difference: [5]E.Q = undefined;
        for (&difference, 0..) |*v, i| v.* = samples[i][c];
        for (0..3) |order| for (0..4 - order) |i| {
            difference[i] = difference[i + 1].sub(difference[i]);
        };
        genuine_cubic = genuine_cubic or !difference[0].isZero();
        try std.testing.expect(difference[1].sub(difference[0]).isZero());
    }
    try std.testing.expect(genuine_cubic);
}

fn secure(x: u32) E.Q {
    return E.Q.fromU32Unchecked(x, x + 1, x + 2, x + 3);
}
fn packedFields(comptime F: type, comptime n: usize, scalar: *[16][n]E.Q, counter: *u32) [n]F {
    var output: [n]F = undefined;
    for (0..n) |i| {
        var base: [16]@import("stwo_core").fields.m31.M31 = undefined;
        var extension: [16]E.Q = undefined;
        for (0..16) |lane| {
            const value = counter.*;
            counter.* += 4;
            base[lane] = .fromCanonical(value);
            extension[lane] = if (F == E.PackedBase) E.q(value) else secure(value);
            scalar[lane][i] = extension[lane];
        }
        output[i] = if (F == E.PackedBase) F.fromLanes(base) else F.fromLanes(extension);
    }
    return output;
}
test "Word16 complete ALU authority preserves all80 residuals across base and arbitrary secure lanes" {
    var ch = P.Challenges{ .range16 = .{ .offset = secure(3), .coefficient = secure(7) }, .function = .{ .offset = secure(11), .coefficients = undefined } };
    for (&ch.function.coefficients, 0..) |*v, i| v.* = secure(@intCast(17 + 4 * i));
    const claims = P.Claims{ .range16 = secure(71), .function = secure(79) };
    inline for (.{ E.PackedBase, E.PackedSecure }) |F| {
        var counter: u32 = 100;
        var main_scalar: [16][P.MAIN]E.Q = undefined;
        var current_scalar: [16][P.INTERACTION]E.Q = undefined;
        var previous_scalar: [16][P.INTERACTION]E.Q = undefined;
        var flag_scalar: [16][2]E.Q = undefined;
        const main = packedFields(F, P.MAIN, &main_scalar, &counter);
        const current = packedFields(F, P.INTERACTION, &current_scalar, &counter);
        const previous = packedFields(F, P.INTERACTION, &previous_scalar, &counter);
        const flags = packedFields(F, 2, &flag_scalar, &counter);
        var residuals: [P.CONSTRAINTS]E.PackedSecure = undefined;
        var sink = E.SinkFor(F){ .values = &residuals };
        P.emitFor(F, &main, &current, &previous, flags[0], flags[1], claims, ch, &sink);
        try std.testing.expectEqual(P.CONSTRAINTS, sink.count);
        for (0..16) |lane| {
            var reference: [P.CONSTRAINTS]E.Q = undefined;
            var scalar_sink = E.Sink{ .values = &reference };
            P.emitFor(E.Q, &main_scalar[lane], &current_scalar[lane], &previous_scalar[lane], flag_scalar[lane][0], flag_scalar[lane][1], claims, ch, &scalar_sink);
            for (residuals, reference) |actual, expected| try std.testing.expect(actual.lane(lane).eql(expected));
        }
    }
}
