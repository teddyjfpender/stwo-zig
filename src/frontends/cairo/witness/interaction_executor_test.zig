//! Coordinate executor contract: direct output, legacy parity and refusal.
const std = @import("std");
const api = @import("interaction_executor.zig");
const trace = @import("interaction_trace.zig");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

const Mock = struct {
    calls: usize = 0,

    fn secure(_: ?*anyopaque, allocator: std.mem.Allocator, _: api.Request) !api.MaterializedTrace {
        const values = try allocator.alloc(QM31, 2);
        values[0] = QM31.fromU32Unchecked(1, 2, 3, 4);
        values[1] = QM31.fromU32Unchecked(5, 6, 7, 8);
        return .{ .allocator = allocator, .values = values, .row_count = 2, .column_count = 1, .claimed_sum = QM31.one() };
    }

    fn forbidden(_: ?*anyopaque, _: std.mem.Allocator, _: api.Request) !api.MaterializedTrace {
        return error.UnexpectedSecureIntermediate;
    }

    fn coordinates(context: ?*anyopaque, _: std.mem.Allocator, _: api.Request, planes: []const []M31) !QM31 {
        const self: *Mock = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        for (planes, 0..) |plane, coordinate| {
            plane[0] = M31.fromU32Unchecked(@intCast(coordinate + 1));
            plane[1] = M31.fromU32Unchecked(@intCast(coordinate + 5));
        }
        return QM31.one();
    }

    fn refuse(_: ?*anyopaque, _: std.mem.Allocator, _: api.Request, _: []const []M31) !QM31 {
        return error.DeviceRefused;
    }
};

const source_words = [_]u32{ 1, 2 };
const source_descriptors = [_]u32{0} ** 16;
fn request() !api.Request {
    return .{
        .descriptors = &source_descriptors,
        .source = try trace.SourceView.lookupWords(try trace.LookupColumns.init(&source_words, 2), 2),
        .z = QM31.one(),
        .alpha_powers = &.{},
    };
}

test "Cairo interaction coordinate executor avoids secure intermediate and matches legacy planes" {
    var direct: [4][2]M31 = undefined;
    var legacy: [4][2]M31 = undefined;
    var direct_planes: [4][]M31 = undefined;
    var legacy_planes: [4][]M31 = undefined;
    for (0..4) |coordinate| {
        direct_planes[coordinate] = &direct[coordinate];
        legacy_planes[coordinate] = &legacy[coordinate];
    }
    var mock = Mock{};
    const executor = api.Executor{ .context = &mock, .execute_fn = Mock.forbidden, .execute_coordinates_fn = Mock.coordinates };
    const direct_sum = try executor.materializeCoordinates(std.testing.allocator, try request(), &direct_planes);
    const legacy_sum = try (api.Executor{ .execute_fn = Mock.secure }).materializeCoordinates(std.testing.allocator, try request(), &legacy_planes);
    try std.testing.expect(direct_sum.eql(legacy_sum));
    try std.testing.expectEqual(@as(usize, 1), mock.calls);
    for (direct, legacy) |a, b| try std.testing.expectEqualSlices(M31, &a, &b);
}

test "Cairo interaction coordinate executor rejects destination geometry before dispatch and propagates refusal" {
    var backing: [4][2]M31 = undefined;
    var planes: [4][]M31 = undefined;
    for (0..4) |coordinate| planes[coordinate] = &backing[coordinate];
    var mock = Mock{};
    const executor = api.Executor{ .context = &mock, .execute_fn = Mock.forbidden, .execute_coordinates_fn = Mock.coordinates };
    try std.testing.expectError(error.InvalidInteractionGeometry, executor.materializeCoordinates(std.testing.allocator, try request(), planes[0..3]));
    planes[3] = backing[3][0..1];
    try std.testing.expectError(error.InvalidInteractionGeometry, executor.materializeCoordinates(std.testing.allocator, try request(), &planes));
    try std.testing.expectEqual(@as(usize, 0), mock.calls);
    planes[3] = &backing[3];
    try std.testing.expectError(error.DeviceRefused, (api.Executor{ .execute_fn = Mock.forbidden, .execute_coordinates_fn = Mock.refuse }).materializeCoordinates(std.testing.allocator, try request(), &planes));
}
