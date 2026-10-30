//! Test-only independent M31 expression oracle, never production witness input.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const P = @import("resident_parent_wire_resolve_plan_v1.zig");
const R = P.Registry;
fn expr(op: R.Op, value: u32, lhs: u32, rhs: u32) R.Expr {
    return .{ .op = @intFromEnum(op), .value = value, .lhs = lhs, .rhs = rhs };
}
pub fn exportVectors(backing: std.mem.Allocator, path: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const a = arena.allocator();
    var registry = try fixture(a);
    defer registry.arena.deinit();
    const ready = [_]P.Ready{ .{ .main_word = 0, .phase = 0 }, .{ .main_word = 1, .phase = 0 }, .{ .main_word = 2, .phase = 0 }, .{ .main_word = 3, .phase = 0 } };
    var p = try P.Plan.init(a, &registry, &.{.{ .consumer = registry.consumers[0], .phase = 1 }}, &ready, .{});
    defer p.deinit();
    var dir = try std.fs.cwd().makeOpenPath(path, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "resolve.cu", .data = @embedFile("resident_parent_wire_resolve_v1.cuh") });
    try dir.writeFile(.{ .sub_path = "numeric_runner.cu", .data = @embedFile("resident_parent_wire_resolve_numeric_runner_v1.cpp") });
    var out: std.Io.Writer.Allocating = .init(a);
    try words(&out.writer, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(p.instructions)));
    try words(&out.writer, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(p.candidates)));
    try words(&out.writer, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(p.requests)));
    const cases = [_][4]u32{ .{ 1, 1, 0, 42 }, .{ 1, 0, 1, 42 }, .{ 1, 1, 1, 42 }, .{ 0, 0, 0, 42 }, .{ 1, 1, 1, 43 }, .{ 1, 0, 0, 42 }, .{ 1, 1, 0, 0x7fffffff }, .{ 1, 1, 0, 0x7ffffffe } };
    try word(&out.writer, cases.len);
    for (cases) |main| {
        try words(&out.writer, &main);
        var expected: [4]u32 = @splat(0);
        var status: u32 = 0;
        var scratch: [64]M = undefined;
        for (p.instructions, 0..) |n, i| {
            scratch[i] = switch (@as(R.Op, @enumFromInt(n.op))) {
                .constant => M.fromCanonical(n.value),
                .main => blk: {
                    if (main[n.value] >= core.fields.m31.Modulus) {
                        status |= 1;
                        break :blk M.zero();
                    }
                    break :blk M.fromCanonical(main[n.value]);
                },
                .add => scratch[n.lhs].add(scratch[n.rhs]),
                .sub => scratch[n.lhs].sub(scratch[n.rhs]),
                .mul => scratch[n.lhs].mul(scratch[n.rhs]),
                .neg => scratch[n.lhs].neg(),
            };
        }
        if (scratch[p.requests[0].weight].v != 0) {
            var seen = false;
            for (p.candidates) |c| {
                if (scratch[c.weight].v == 0) continue;
                var value: [4]u32 = undefined;
                for (c.coordinates, &value) |v, *dest| dest.* = scratch[v].v;
                if (!seen) {
                    expected = value;
                    seen = true;
                } else if (!std.mem.eql(u32, &expected, &value)) status |= 4;
            }
            if (!seen) status |= 2;
        }
        try words(&out.writer, &expected);
        try word(&out.writer, status);
    }
    try dir.writeFile(.{ .sub_path = "numeric.bin", .data = out.written() });
}
fn fixture(a: std.mem.Allocator) !R.Plan {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const b = arena.allocator();
    const expressions = try b.dupe(R.Expr, &[_]R.Expr{ expr(.constant, 0, 0, 0), expr(.constant, 1, 0, 0), expr(.main, 0, 0, 0), expr(.main, 1, 0, 0), expr(.main, 2, 0, 0), expr(.main, 3, 0, 0), expr(.constant, 42, 0, 0), expr(.neg, 0, 2, 0), expr(.add, 0, 5, 1), expr(.sub, 0, 8, 1), expr(.mul, 0, 9, 1) });
    return .{ .a = a, .arena = arena, .program_id = @splat(17), .main_words = 4, .expressions = expressions, .candidates = @constCast(&[_]R.Candidate{ .{ .endpoint = 7, .cohort = 6, .row = 0, .weight = 3, .coordinates = .{ 10, 0, 0, 0 } }, .{ .endpoint = 7, .cohort = 6, .row = 1, .weight = 4, .coordinates = .{ 6, 0, 0, 0 } } }), .endpoints = @constCast(&[_]R.Endpoint{.{ .key = 7, .first = 0, .count = 2 }}), .consumers = @constCast(&[_]R.Consumer{.{ .main_word = 0, .limb = 0, .endpoint = 7, .cohort = 14, .row = 0, .weight = 7 }}), .unresolved = &.{} };
}
fn word(w: anytype, x: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, x, .little);
    try w.writeAll(&b);
}
fn words(w: anytype, x: []align(1) const u32) !void {
    try word(w, @intCast(x.len));
    for (x) |v| try word(w, v);
}
test "resident wire resolver rejects unavailable future and untrusted dependencies" {
    const a = std.testing.allocator;
    var r = try fixture(a);
    defer r.arena.deinit();
    var ready = [_]P.Ready{ .{ .main_word = 0, .phase = 0 }, .{ .main_word = 1, .phase = 0 }, .{ .main_word = 2, .phase = 0 }, .{ .main_word = 3, .phase = 0 } };
    const requests = [_]P.Proposal{.{ .consumer = r.consumers[0], .phase = 1 }};
    var p = try P.Plan.init(a, &r, &requests, &ready, .{});
    defer p.deinit();
    try std.testing.expectEqual(p.instructions.len, p.scratch_words);
    try std.testing.expectEqual(@as(usize, 4), p.output_words);
    ready[2].phase = 1;
    try std.testing.expectError(error.FutureResidentWireDependency, P.Plan.init(a, &r, &requests, &ready, .{}));
    ready[2].phase = 0;
    try std.testing.expectError(error.UninitializedResidentWireDependency, P.Plan.init(a, &r, &requests, ready[0..3], .{}));
    var bad = requests;
    bad[0].consumer.endpoint = 8;
    try std.testing.expectError(error.UntrustedResidentWireConsumer, P.Plan.init(a, &r, &bad, &ready, .{}));
    try std.testing.expectError(error.ResidentWireResolveResourceLimit, P.Plan.init(a, &r, &requests, &ready, .{ .max_bytes = 1 }));
    var inactive_consumer = [_]R.Consumer{r.consumers[0]};
    inactive_consumer[0].weight = 0;
    r.consumers = &inactive_consumer;
    var inactive = try P.Plan.init(a, &r, &.{.{ .consumer = inactive_consumer[0], .phase = 1 }}, &.{}, .{});
    defer inactive.deinit();
    try std.testing.expectEqual(@as(usize, 0), inactive.candidates.len);
    try std.testing.expectEqual(@as(usize, 1), inactive.instructions.len);
}
