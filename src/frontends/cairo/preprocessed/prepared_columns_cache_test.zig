const std = @import("std");
const core = @import("stwo_core");
const cache = @import("product_cache.zig");
const integrity = @import("tree_digest_cache.zig");
const Request = @import("stwo_prover_engine").pcs.column_preparation_cache.Request;
const M31 = core.fields.m31.M31;
const support = @import("prepared_columns_cache.zig").testing;
const Session = support.Session;
const payloadBytes = support.payloadBytes;
const keyFor = support.keyFor;
const load = support.load;
const store = support.store;
const viewsFor = support.viewsFor;
const header = support.header;
const pathFor = support.pathFor;
const header_bytes = support.header_bytes;
const maximum_payload = support.maximum_payload;
const Fixture = struct {
    request: Request = .{ .base_log_size = 3, .extended_log_size = 4, .column_count = 2 },
    sources: [2][8]M31 = undefined,
    coefficients: [2][8]M31 = undefined,
    evaluations: [2][16]M31 = undefined,

    fn init() Fixture {
        var fixture = Fixture{};
        for (&fixture.sources, &fixture.coefficients, &fixture.evaluations, 0..) |*source, *coefficient, *evaluation, index| {
            for (source, coefficient, 0..) |*s, *c, row| {
                s.* = .{ .v = @intCast(index * 31 + row) };
                c.* = .{ .v = @intCast(index * 53 + row * 3) };
            }
            for (evaluation, 0..) |*e, row| e.* = .{ .v = @intCast(index * 97 + row * 7) };
        }
        return fixture;
    }
    fn sourceViews(self: *const Fixture) [2][]const M31 {
        return .{ &self.sources[0], &self.sources[1] };
    }
    fn coefficientViews(self: *Fixture) [2][]M31 {
        return .{ &self.coefficients[0], &self.coefficients[1] };
    }
    fn evaluationViews(self: *Fixture) [2][]M31 {
        return .{ &self.evaluations[0], &self.evaluations[1] };
    }
};

test "prepared public column identity binds content order and protocol" {
    const saved = cache.currentConfig();
    defer cache.configure(saved);
    cache.configure(.{ .enabled = true, .directory = "/unused", .product_digest = @splat(9) });
    var state = Session{ .allocator = std.testing.allocator, .binding = .{ .variant = .canonical, .spec_digest = @splat(1), .pcs_digest = @splat(2) }, .recorder = null, .remaining = maximum_payload };
    var fixture = Fixture.init();
    const key = try keyFor(&state, fixture.request, &fixture.sourceViews());
    var reordered = fixture.sourceViews();
    std.mem.swap([]const M31, &reordered[0], &reordered[1]);
    try std.testing.expect(!std.mem.eql(u8, &key, &try keyFor(&state, fixture.request, &reordered)));
    fixture.sources[1][7].v += 1;
    try std.testing.expect(!std.mem.eql(u8, &key, &try keyFor(&state, fixture.request, &fixture.sourceViews())));
    fixture.sources[1][7].v -= 1;
    state.binding.pcs_digest[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &key, &try keyFor(&state, fixture.request, &fixture.sourceViews())));
    state.binding.pcs_digest[0] ^= 1;
    state.binding.variant = .canonical_small;
    try std.testing.expect(!std.mem.eql(u8, &key, &try keyFor(&state, fixture.request, &fixture.sourceViews())));
    try std.testing.expectError(error.PreparedCacheUnusable, payloadBytes(.{ .base_log_size = 32, .extended_log_size = 31, .column_count = 1 }));
    try std.testing.expectError(error.Overflow, payloadBytes(.{ .base_log_size = 3, .extended_log_size = 4, .column_count = std.math.maxInt(usize) }));
}

test "prepared public column cache validates before publishing in-place values" {
    const allocator = std.testing.allocator;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const absolute = try directory.dir.realpathAlloc(allocator, ".");
    defer allocator.free(absolute);
    const saved = cache.currentConfig();
    defer cache.configure(saved);
    cache.configure(.{ .enabled = true, .directory = absolute, .product_digest = @splat(9) });
    var state = Session{ .allocator = allocator, .binding = .{ .variant = .canonical, .spec_digest = @splat(1), .pcs_digest = @splat(2) }, .recorder = null, .remaining = maximum_payload };
    var expected = Fixture.init();
    const key = try keyFor(&state, expected.request, &expected.sourceViews());
    try store(&state, key, expected.request, &expected.coefficientViews(), &expected.evaluationViews());
    var actual = Fixture.init();
    for (&actual.coefficients) |*column| @memset(column, M31.zero());
    for (&actual.evaluations) |*column| @memset(column, M31.zero());
    try load(&state, key, actual.request, &actual.coefficientViews(), &actual.evaluationViews());
    for (actual.coefficients, expected.coefficients) |a, e| try std.testing.expectEqualSlices(M31, &e, &a);
    for (actual.evaluations, expected.evaluations) |a, e| try std.testing.expectEqualSlices(M31, &e, &a);

    // Load into the original source arrays, as CPU in-place IFFT does. Every
    // failed artifact must leave both those arrays and evaluations untouched.
    const destinations = actual.sourceViews();
    const coefficient_destinations = [_][]M31{ @constCast(destinations[0]), @constCast(destinations[1]) };
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try pathFor(&path_buffer, key);
    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    defer file.close();
    const original = actual;
    const corruptions = [_]u64{ 0, header_bytes + 4, header_bytes + try payloadBytes(actual.request) };
    for (corruptions) |offset| {
        try store(&state, key, expected.request, &expected.coefficientViews(), &expected.evaluationViews());
        // Atomic publication replaces the inode, so open the newly stored file.
        const corrupt = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
        defer corrupt.close();
        var byte: [1]u8 = undefined;
        _ = try corrupt.preadAll(&byte, offset);
        byte[0] ^= 1;
        try corrupt.pwriteAll(&byte, offset);
        try std.testing.expectError(error.PreparedCacheUnusable, load(&state, key, actual.request, &coefficient_destinations, &actual.evaluationViews()));
        try std.testing.expectEqualDeep(original, actual);
    }
    try store(&state, key, expected.request, &expected.coefficientViews(), &expected.evaluationViews());
    const truncated = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    defer truncated.close();
    try truncated.setEndPos(header_bytes + 5);
    try std.testing.expectError(error.PreparedCacheUnusable, load(&state, key, actual.request, &coefficient_destinations, &actual.evaluationViews()));
    try std.testing.expectEqualDeep(original, actual);

    // A checksum alone cannot legitimize a noncanonical field encoding.
    expected.coefficients[0][0].v = core.fields.m31.Modulus;
    try std.testing.expectError(error.PreparedCacheUnusable, store(&state, key, expected.request, &expected.coefficientViews(), &expected.evaluationViews()));
    const views = try viewsFor(allocator, expected.request, &expected.coefficientViews(), &expected.evaluationViews());
    defer allocator.free(views);
    const artifact_header = try header(key, expected.request);
    const digest = try integrity.integrityDigest(allocator, &artifact_header, views);
    const forged = try std.fs.createFileAbsolute(path, .{});
    defer forged.close();
    try forged.writeAll(&artifact_header);
    for (views) |view| try forged.writeAll(view);
    try forged.writeAll(&digest);
    try std.testing.expectError(error.PreparedCacheUnusable, load(&state, key, actual.request, &coefficient_destinations, &actual.evaluationViews()));
    try std.testing.expectEqualDeep(original, actual);
}
