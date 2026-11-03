//! Independent lookup repetition construction. This is not an accepting proof
//! profile: the legacy circuit receiver still expects one interaction lane.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const trace = @import("trace.zig");
const preprocessed = @import("../common/preprocessed.zig");
const List = @import("../common/component_list.zig");
const Q = core.fields.qm31.QM31;
const Col = prover.pcs.ColumnEvaluation;
pub const Elements = core.channel.lookup_transcript.LookupElements;
pub const Claims = List.PerComponent(Q);

pub const Interaction = struct {
    allocator: std.mem.Allocator,
    /// Lane0's complete native component roster, then lane1's roster.
    columns: []Col,
    columns_per_lane: usize,
    claimed_sums: [2]Claims,
    pub fn deinit(self: *@This()) void {
        trace.freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }
    pub fn takeColumns(self: *@This()) []Col {
        const result = self.columns;
        self.columns = &.{};
        return result;
    }
};

pub fn requireDistinct(elements: [2]Elements) !void {
    if (elements[0].z.eql(elements[1].z) and elements[0].alpha.eql(elements[1].alpha)) return error.ReusedLookupChallenge;
}

/// Each lane must close separately. Checking only their sum would permit a
/// forged +delta/-delta pair to cancel between independent lookup arguments.
pub fn validateClaims(outputs: []const Q, claims: [2]Claims, elements: [2]Elements) !void {
    try requireDistinct(elements);
    for (claims, elements) |lane, pair| {
        if (!(try trace.lookupSum(outputs, lane, pair.z, pair.alpha)).isZero()) return error.InvalidRepeatedLookupSum;
    }
}

/// Failure atomic: both INTER witnesses, independent closure and the final
/// descriptor allocation succeed before the sole MAIN owner is retired.
/// Existing legacy generation/release order is untouched.
pub fn generateReleasing(a: std.mem.Allocator, base: *trace.BaseTrace, pp: *const preprocessed.PreprocessedCircuit, elements: [2]Elements) !Interaction {
    try requireDistinct(elements);
    var lanes: [2]trace.InteractionTrace = undefined;
    var made: usize = 0;
    defer for (lanes[0..made]) |*lane| lane.deinit();
    for (&lanes, elements) |*lane, pair| {
        lane.* = try trace.writeInteractionTrace(a, base.columns, base.log_sizes, pp, pair.z, pair.alpha);
        made += 1;
    }
    try validateClaims(base.output_values, .{ lanes[0].claimed_sums, lanes[1].claimed_sums }, elements);
    const result = try takeLanes(a, &lanes);
    // No fallible work follows this transfer; output values remain available
    // for statement framing and public lookup terms.
    trace.freeColumns(base.allocator, base.takeColumns());
    return result;
}

fn takeLanes(a: std.mem.Allocator, lanes: *[2]trace.InteractionTrace) !Interaction {
    if (lanes[0].columns.len != lanes[1].columns.len) return error.LookupRepetitionShapeMismatch;
    const count = lanes[0].columns.len;
    const columns = try a.alloc(Col, try std.math.mul(usize, count, 2));
    @memcpy(columns[0..count], lanes[0].columns);
    @memcpy(columns[count..], lanes[1].columns);
    for (lanes) |*lane| {
        lane.allocator.free(lane.columns);
        lane.columns = &.{};
    }
    return .{ .allocator = a, .columns = columns, .columns_per_lane = count, .claimed_sums = .{ lanes[0].claimed_sums, lanes[1].claimed_sums } };
}

fn pairs() [2]Elements {
    return .{ .{ .z = Q.fromU32Unchecked(17, 2, 3, 4), .alpha = Q.fromU32Unchecked(5, 6, 7, 8) }, .{ .z = Q.fromU32Unchecked(19, 3, 5, 7), .alpha = Q.fromU32Unchecked(11, 13, 17, 19) } };
}
fn emptyClaims() Claims {
    return Claims.fromArray(@splat(Q.zero()));
}
test "repeat2 independent closure rejects balanced cross-lane debt and reused challenges" {
    const elements = pairs();
    var claims: [2]Claims = .{ emptyClaims(), emptyClaims() };
    for (&claims, elements) |*lane, pair| lane.eq = (try trace.lookupSum(&.{}, lane.*, pair.z, pair.alpha)).neg();
    try validateClaims(&.{}, claims, elements);
    claims[0].eq = claims[0].eq.add(Q.one());
    claims[1].eq = claims[1].eq.sub(Q.one());
    try std.testing.expectError(error.InvalidRepeatedLookupSum, validateClaims(&.{}, claims, elements));
    try std.testing.expectError(error.ReusedLookupChallenge, requireDistinct(.{ elements[0], elements[0] }));
}
fn makeLane(a: std.mem.Allocator, value: u32) !trace.InteractionTrace {
    const columns = try a.alloc(Col, 1);
    errdefer a.free(columns);
    const values = try a.alloc(core.fields.m31.M31, 2);
    @memset(values, core.fields.m31.M31.fromCanonical(value));
    columns[0] = .{ .log_size = 1, .values = values };
    return .{ .allocator = a, .columns = columns, .claimed_sums = emptyClaims() };
}
test "repeat2 lane assembly transfers planes once and allocation failure preserves both owners" {
    const a = std.testing.allocator;
    var lanes = [2]trace.InteractionTrace{ try makeLane(a, 3), try makeLane(a, 7) };
    defer for (&lanes) |*lane| lane.deinit();
    const first = lanes[0].columns[0].values.ptr;
    const second = lanes[1].columns[0].values.ptr;
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, takeLanes(failing.allocator(), &lanes));
    try std.testing.expectEqual(first, lanes[0].columns[0].values.ptr);
    try std.testing.expectEqual(second, lanes[1].columns[0].values.ptr);
    var result = try takeLanes(a, &lanes);
    defer result.deinit();
    try std.testing.expectEqual(first, result.columns[0].values.ptr);
    try std.testing.expectEqual(second, result.columns[1].values.ptr);
    try std.testing.expectEqual(@as(usize, 0), lanes[0].columns.len);
    try std.testing.expectEqual(@as(usize, 0), lanes[1].columns.len);
}

test "repeat2 generation rejects malformed MAIN without taking its owner" {
    var base = trace.BaseTrace{ .allocator = std.testing.allocator, .log_sizes = List.PerComponent(u32).fromArray(@splat(5)), .columns = &.{}, .output_values = &.{} };
    defer base.deinit();
    // The empty base is rejected before preprocessed rows are consulted.
    var pp: preprocessed.PreprocessedCircuit = undefined;
    try std.testing.expectError(error.InvalidTraceShape, generateReleasing(std.testing.allocator, &base, &pp, pairs()));
    try std.testing.expectEqual(@as(usize, 0), base.columns.len);
}
