const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
const Prefix = @import("block_v7_epoch_transcript_v1.zig");
const Recorder = @import("blake3_native_recorder.zig");
const Sink = @import("blake3_fixed_operation_recorder_v1.zig");
const Plan = @import("blake3_transcript_plan.zig").Plan;
const T = @import("blake3_transcript_witness.zig");
test "v7 epoch single draws bind every native challenge limb and half route" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const config = @import("../blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.native)] = 1;
    const entries = [_]E.Entry{try E.Entry.init(.native, 0, @splat(1), &.{@splat(2)})};
    const epoch = try E.Epoch.init(@splat(3), config, counts, &entries, 1);
    var live = Recorder.Recorder{ .a = temp, .universal_relations = true };
    var cold = Sink.Recorder{ .a = temp, .limits = .{} };
    inline for (.{ &live, &cold }) |r| {
        r.mixU32s(&.{ 0x42374550, E.VERSION, 2 });
        r.mixPublicRoot(.{ .circuit = 4_200_031, .first_wire = 0 }, epoch.digest);
    }
    try Prefix.live(temp, &live);
    try Prefix.fixed(temp, &cold);
    const drawn = try epoch.draw(temp);
    try std.testing.expectEqualDeep(drawn.channel, live.native); // BEFORE any reset/mix
    const actual = try @import("block_v7_memory_joint_inputs_v1.zig").challenges(temp, epoch);
    var seen: [106]bool = @splat(false);
    for (live.operations.items) |operation| if (operation == .secure) {
        const draw = operation.secure;
        const first = switch (draw.output.?) {
            .universal => |i| 2 * i,
            .universal_half => |half| 2 * half.relation + half.half,
            else => return error.UnexpectedEpochRole,
        };
        for (0..draw.consumption.words() / 4) |i| {
            try std.testing.expect(!seen[first + i]);
            seen[first + i] = true;
            try std.testing.expectEqualDeep(actual[first + i].toM31Array(), draw.values[4 * i ..][0..4].*);
        }
    };
    for (seen) |present| try std.testing.expect(present);
    var l = try Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = 2 }, live.operations.items);
    defer l.deinit();
    var c = try Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = 2 }, cold.operations.items);
    defer c.deinit();
    try std.testing.expectEqualDeep(l.id, c.id);
    const last = cold.operations.items.len - 1;
    cold.operations.items[last].secure.output.?.universal_half.half = 0;
    var changed = try Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = 2 }, cold.operations.items);
    defer changed.deinit();
    try std.testing.expect(!std.meta.eql(c.id, changed.id));

    const Deep = @import("pcs_deep_circuit.zig");
    const Fri = @import("fri_verifier_circuit.zig");
    var dg = try Deep.build(a, .{ .trees = &.{.{ .column_log_sizes = &.{3} }}, .sample_layouts = &.{.current}, .lifting_log_size = 3, .log_blowup_factor = 1, .query_count = 1 });
    defer dg.deinit();
    var fg = try Fri.build(a, .{ .lifting_log_size = 3, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .query_count = 1, .fold_widths = &.{4} });
    defer fg.deinit();
    var outputs: std.ArrayList(T.DrawOutput) = .empty;
    defer outputs.deinit(a);
    try outputs.appendSlice(a, l.fixed.draw_outputs);
    for ([_]T.OutputRole{ .composition, .oods, .deep, .{ .fri = 0 } }, 0..) |role, i| try outputs.append(a, .{ .operation = 100 + i, .role = role, .source = .{ .circuit = @intCast(1000 + i), .first_wire = 0 }, .words = 4 });
    const Links = @import("blake3_challenge_links.zig");
    const sources = Links.Sources{ .sample_start = 0, .claim_start = 0, .composition = 106, .oods = 107, .universal_start = 0 };
    const links = try Links.build(a, outputs.items, sources, &dg, &fg, 53, 1);
    defer a.free(links);
    try std.testing.expectEqual(@as(usize, 110), links.len);
    const i = l.fixed.draw_outputs.len - 1;
    const saved = outputs.items[i];
    outputs.items[i].role.universal_half.half = 0;
    try std.testing.expectError(error.InvalidParentChallengeLink, Links.build(a, outputs.items, sources, &dg, &fg, 53, 1));
    outputs.items[i] = saved;
    outputs.items[i].words = 8;
    try std.testing.expectError(error.InvalidParentChallengeLink, Links.build(a, outputs.items, sources, &dg, &fg, 53, 1));
    outputs.items[i] = saved;
    outputs.items[i].role.universal_half.relation = 53;
    try std.testing.expectError(error.InvalidParentChallengeLink, Links.build(a, outputs.items, sources, &dg, &fg, 53, 1));
}
