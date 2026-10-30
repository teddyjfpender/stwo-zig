//! Discarding a value removes a fixed-value boundary, never its authenticated
//! hash, rejection, first-accepted selection or counter relations.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const T = @import("../blake3_transcript_witness.zig");
const Plan = @import("../blake3_transcript_plan.zig").Plan;
const Airs = .{ T.g, T.xor, T.boundary, T.challenge, T.route, T.query_mask, T.retry_control, T.counter_step };
fn rows(v: *const T.Prepared) @TypeOf(.{ v.g_rows, v.xor_rows, v.boundary_rows, v.challenge_rows, v.route_rows, v.query_rows, v.control_rows, v.counter_rows }) {
    return .{ v.g_rows, v.xor_rows, v.boundary_rows, v.challenge_rows, v.route_rows, v.query_rows, v.control_rows, v.counter_rows };
}
test "BLAKE3 discarded draw has seed-independent fixed rows and constrained selection counters" {
    const a = std.testing.allocator;
    var ops = [_]T.Operation{
        .{ .routed_integer = .{ .value = 42, .source = .{ .circuit = 10, .first_wire = 0 } } },
        .{ .secure = .{ .discard_output = true, .attempts = 0, .consumption = .two, .values = @splat(M.zero()) } },
    };
    var key = try Plan.initCompact(a, .{ .namespace = 100, .attempt_capacity = 3 }, &ops);
    defer key.deinit();
    var live = try T.prepareBounded(a, 100, &ops, 3);
    defer live.deinit();
    var native = core.channel.blake3.Channel{};
    native.mixU64(42);
    const expected = try native.drawSecureFelts(a, 2);
    defer a.free(expected);
    try std.testing.expectEqual(native.n_draws, live.next_draw);
    try std.testing.expectEqualSlices(u8, &native.digestBytes(), &live.final_digest.?);
    try std.testing.expectEqual(@as(usize, 0), live.draw_outputs.len);
    const before = try wireSum(a, &live);
    // Selected coordinate participates in the hash-to-control and control-to-
    // sink wire relations even though it has no exported arithmetic consumer.
    const selected = for (live.control_rows, 0..) |row, i| {
        if (row[2].v == 1) break i;
    } else return error.MissingSelectedDraw;
    live.control_rows[selected][4] = live.control_rows[selected][4].add(M.one());
    try std.testing.expect(!before.eql(try wireSum(a, &live)));
    live.control_rows[selected][4] = live.control_rows[selected][4].sub(M.one());
    live.counter_rows[0][0] = live.counter_rows[0][0].add(M.one());
    try std.testing.expect(!before.eql(try wireSum(a, &live)));
    live.counter_rows[0][0] = live.counter_rows[0][0].sub(M.one());
    try std.testing.expect(before.eql(try wireSum(a, &live)));
    ops[0].routed_integer.value = 987654;
    ops[1].secure.values = @splat(M.one());
    var changed_key = try Plan.initCompact(a, key.config, &ops);
    defer changed_key.deinit();
    try std.testing.expectEqualSlices(u8, &key.id, &changed_key.id);
    var changed = try key.prepare(a, &ops);
    defer changed.deinit();
    try std.testing.expect(!std.mem.eql(u8, &live.final_digest.?, &changed.final_digest.?));
    ops[1].secure.discard_output = false;
    var pinned = try Plan.initCompact(a, key.config, &ops);
    defer pinned.deinit();
    try std.testing.expect(!std.mem.eql(u8, &key.id, &pinned.id));
    try std.testing.expectError(error.Blake3TranscriptPlanMismatch, key.prepare(a, &ops));
    ops[1].secure.values[0] = M.zero();
    var different_expected = try Plan.initCompact(a, key.config, &ops);
    defer different_expected.deinit();
    try std.testing.expect(!std.mem.eql(u8, &pinned.id, &different_expected.id));
    ops[1].secure.discard_output = true;
    ops[1].secure.output = .oods;
    try std.testing.expectError(error.InvalidBlake3Transcript, Plan.initCompact(a, key.config, &ops));
    ops[1].secure.output = null;
    try std.testing.expectError(error.InvalidBlake3Transcript, T.prepare(a, 100, &ops));
}
fn wireSum(a: std.mem.Allocator, data: *const T.Prepared) !Q {
    const Relation = @import("../../../air/lang/relation.zig");
    const Universal = @import("../universal_challenges.zig").UniversalRelations;
    var channel = core.channel.blake3.Channel{};
    const relations = try Universal.draw(a, &channel);
    const Visitor = struct {
        relation: @TypeOf(relations.get(.recursion_wire)),
        sum: Q = Q.zero(),
        pub fn accepts(_: *@This(), id: anytype) bool {
            return id == Relation.id(.recursion_wire);
        }
        pub fn visit(self: *@This(), _: anytype, numerator: M, values: []const M) !void {
            self.sum = self.sum.add(Q.fromBase(numerator).mul(try (try self.relation.combineBase(values)).inv()));
        }
    };
    var visitor = Visitor{ .relation = relations.get(.recursion_wire) };
    inline for (Airs, rows(data)) |Air, part| {
        var definition = try Air.build(a);
        defer definition.deinit();
        const binding = try @import("../universal_relation_binding.zig").Binding(Air).authenticate(&definition);
        for (part) |row| try binding.visitPreparedBaseEntries(row, &visitor);
    }
    return visitor.sum;
}
