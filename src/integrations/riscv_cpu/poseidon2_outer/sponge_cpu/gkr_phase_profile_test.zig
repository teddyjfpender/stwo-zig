//! Tiny closed lookup projection fixture, NOT a CPU/execution admission test.
//! Uses the actual sponge-CPU provider, child codec and checkpointed engine.
const std = @import("std");
const E = @import("stwo_prover_engine");
const P = E.stage_profile;
const Timing = E.lookups.gkr_profile;
const C = @import("stwo_core");
const O = C.fields.om31.OM31;
const Native = @import("native.zig");
const Frame = @import("frame.zig");
const Provider = @import("provider.zig");
const Sources = @import("../../word16_global_execution/services/roster.zig").Sources;
fn errorScope(recorder: *P.Recorder) !void {
    var scope = Timing.Scope.init(recorder);
    defer scope.deinit();
    var stage = try Timing.begin("failing", "Error unwind");
    defer stage.end();
    return error.InjectedProfileError;
}
test "OP CPU GKR profiling scopes restore nested disabled error and helper thread state" {
    const a = std.testing.allocator;
    var outer = P.Recorder.initWithOptions(a, "unit", "outer", .{ .capture_tasks = false });
    defer outer.deinit();
    var inner = P.Recorder.initWithOptions(a, "unit", "inner", .{ .capture_tasks = false });
    defer inner.deinit();
    var off = try Timing.begin("off", "Disabled");
    try std.testing.expect(off.recorder == null);
    off.end();
    {
        var scope = Timing.Scope.init(&outer);
        defer scope.deinit();
        var first = try Timing.begin("first", "Outer");
        first.end();
        {
            var disabled = Timing.Scope.init(null);
            defer disabled.deinit();
            var hidden = try Timing.begin("hidden", "Disabled nested");
            try std.testing.expect(hidden.recorder == null);
            hidden.end();
        }
        try std.testing.expectError(error.InjectedProfileError, errorScope(&inner));
        const Helper = struct {
            fn run(disabled: *bool) void {
                var stage = Timing.begin("helper", "Helper must be disabled") catch unreachable;
                disabled.* = stage.recorder == null;
                stage.end();
            }
        };
        var helper_disabled = false;
        const thread = try std.Thread.spawn(.{}, Helper.run, .{&helper_disabled});
        thread.join();
        try std.testing.expect(helper_disabled);
        var last = try Timing.begin("last", "Outer restored");
        last.end();
    }
    var done = try Timing.begin("done", "Disabled again");
    try std.testing.expect(done.recorder == null);
    done.end();
    var out = try outer.snapshot(a);
    defer out.deinit(a);
    var inside = try inner.snapshot(a);
    defer inside.deinit(a);
    try std.testing.expectEqual(@as(usize, 2), out.stages.len);
    try std.testing.expectEqualStrings("first", out.stages[0].id);
    try std.testing.expectEqualStrings("last", out.stages[1].id);
    try std.testing.expectEqual(@as(usize, 1), inside.stages.len);
}
test "OP CPU GKR coarse phases preserve child proof receipt eta and engine channel bytes" {
    const a = std.testing.allocator;
    var counts = [_]u64{0} ** 32;
    counts[0] = 32;
    // Only these two fields are reachable through the explicit table-only
    // instances below. Borrowed partial sources are never deinitialized or
    // admitted as physical CPU tables. Every padded frontier row contributes
    // +1 to U16/U8(0), canceled by table weight-32 at row0.
    var sources: Sources = undefined;
    sources.core.range16.counts = &counts;
    sources.core.range8.counts = &counts;
    var frontier = try @import("source.zig").Source.init(a, &.{}, 0, 5, 1, 0);
    defer frontier.deinit();
    const provider = Provider.Provider{ .legacy = .{ .source = &sources }, .frontier = &frontier };
    const instances = [_]Frame.Instance{
        .{ .legacy = .{ .origin = .{ .core = .range16 }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 } },
        .{ .legacy = .{ .origin = .{ .core = .range8 }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 } },
        .{ .frontier = .{ .row_log = 5, .fixed_offset = 0, .main_offset = 0 } },
    };
    const hash = @import("../pure_p2_native.zig").hashWords;
    const source_scope = Native.Scope{ .statement = @splat(11), .fixed = hash(&.{123}), .main = hash(&.{456}), .ordinal = 0, .epoch = 1, .calls = 0 };
    var plain = try Native.proveUnbound(a, source_scope, &instances, provider);
    defer plain.deinit(a);
    const expected = try Native.encode(a, &instances, &plain.result.proof);
    defer a.free(expected);
    var recorder = P.Recorder.initWithOptions(a, "unit", "GKR exact bytes", .{ .capture_tasks = false });
    defer recorder.deinit();
    {
        var scope = Timing.Scope.init(&recorder);
        defer scope.deinit();
        var actual = try Native.proveUnbound(a, source_scope, &instances, provider);
        defer actual.deinit(a);
        const encoded = try Native.encode(a, &instances, &actual.result.proof);
        defer a.free(encoded);
        try std.testing.expectEqualSlices(u8, expected, encoded);
        try std.testing.expectEqualSlices(u8, &plain.digest, &actual.digest);
        try std.testing.expect(plain.eta.eql(actual.eta));
        var checked = try Native.verifyPending(a, source_scope, &instances, &actual.result.proof, actual.digest);
        defer checked.deinit(a);
        try std.testing.expect(checked.eta.eql(actual.eta));
    }
    var profile = try recorder.snapshot(a);
    defer profile.deinit(a);
    const ids = [_][]const u8{ "gkr_source_tree_construction", "gkr_sumcheck_traversal", "gkr_terminal_artifact", "gkr_terminal_receipt", "gkr_wire_encoding" };
    try std.testing.expectEqual(ids.len, profile.stages.len);
    for (profile.stages, ids) |stage, id| try std.testing.expectEqualStrings(id, stage.id);
    // Direct engine channels are compared in full, including draw counter and
    // transcript digest, then observed through the following challenge draw.
    var channel0 = try Native.begin(source_scope, &instances);
    _ = Provider.Challenges.draw(&channel0);
    var channel1 = channel0;
    var inputs = try @import("source_inputs.zig").Batch.init(a, &instances, plain.challenges, provider);
    defer inputs.deinit();
    const GP = E.lookups.gkr_prover.ForField(O);
    var base = try GP.proveBatchSourceCheckpointed(a, &channel0, inputs.sources);
    defer base.deinit(a);
    {
        var scope = Timing.Scope.init(&recorder);
        defer scope.deinit();
        var timed = try GP.proveBatchSourceCheckpointed(a, &channel1, inputs.sources);
        defer timed.deinit(a);
    }
    try std.testing.expectEqualDeep(channel0, channel1);
    try std.testing.expect(channel0.drawSecureFelt().eql(channel1.drawSecureFelt()));
    // Recorder failure must cleanly unwind source/tree allocations and restore
    // the disabled coordinator scope. It is not a transcript retry API.
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var bad_recorder = P.Recorder.initWithOptions(failing.allocator(), "unit", "injected OOM", .{ .capture_tasks = false });
    defer bad_recorder.deinit();
    {
        var scope = Timing.Scope.init(&bad_recorder);
        defer scope.deinit();
        try std.testing.expectError(error.OutOfMemory, Native.proveUnbound(a, source_scope, &instances, provider));
    }
    var disabled = try Timing.begin("disabled", "After OOM");
    try std.testing.expect(disabled.recorder == null);
    disabled.end();
}

test "OP CPU GKR shared telemetry leaves QM31 control proof and channel unchanged" {
    const a = std.testing.allocator;
    const Q = C.fields.qm31.QM31;
    const GP = E.lookups.gkr_prover.ForField(Q);
    const Reader = struct {
        fn read(_: *const anyopaque, first: usize, n: []C.fields.m31.M31, d: []Q) error{ OutOfMemory, ShapeMismatch, InvalidLayerStructure }!void {
            if (n.len != d.len or first > 32 or n.len > 32 - first) return error.ShapeMismatch;
            @memset(n, C.fields.m31.M31.zero());
            @memset(d, Q.one());
        }
    };
    const borrowed: u8 = 0;
    const source = GP.MultiplicitiesSource{ .variables = 5, .context = &borrowed, .wide_reads = true, .read_fn = Reader.read };
    var plain_channel: C.channel.blake2s.Blake2sChannel = .{};
    var timed_channel = plain_channel;
    var plain = try GP.proveBatchSourceCheckpointed(a, &plain_channel, &.{source});
    defer plain.deinit(a);
    var recorder = P.Recorder.initWithOptions(a, "unit", "QM31 control", .{ .capture_tasks = false });
    defer recorder.deinit();
    {
        var scope = Timing.Scope.init(&recorder);
        defer scope.deinit();
        var timed = try GP.proveBatchSourceCheckpointed(a, &timed_channel, &.{source});
        defer timed.deinit(a);
        try std.testing.expectEqualDeep(plain.proof, timed.proof);
        try std.testing.expectEqualDeep(plain.artifact, timed.artifact);
    }
    try std.testing.expectEqualDeep(plain_channel, timed_channel);
    try std.testing.expect(plain_channel.drawSecureFelt().eql(timed_channel.drawSecureFelt()));
}
