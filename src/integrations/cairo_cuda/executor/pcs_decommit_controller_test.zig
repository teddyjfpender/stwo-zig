const std = @import("std");
const column = @import("../../../backends/cuda/runtime/column.zig");
const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const telemetry = @import(
    "../../../backends/cuda/runtime/telemetry.zig",
);
const pcs_hooks = @import("pcs_hooks.zig");
const transcript_controller = @import("transcript/controller.zig");
const transcript_schedule = @import("transcript/schedule.zig");
const fixture_module = @import("pcs_controller_test_fixture.zig");
const subject = @import("pcs_decommit_controller.zig");

test "SN2 decommit controller derives queries and seals terminal route" {
    const allocator = std.testing.allocator;
    var fixture = try fixture_module.Fixture.init(allocator);
    defer fixture.deinit();
    const provider = fixture_module.Provider{ .plan = &fixture.plan };
    const bindings = try pcs_hooks.bind(
        provider,
        &fixture.plan,
        fixture.program,
        fixture.protocol,
    );
    const schedule = try transcript_schedule.Schedule.init(
        fixture.program,
        fixture.protocol,
    );
    var session = FakeSession{ .context = .{ .active_stage = .ingress } };
    var prepared = try subject.prepare(
        allocator,
        &session,
        &fixture.plan,
        fixture.program,
        fixture.protocol,
        bindings,
        schedule,
    );
    defer prepared.deinit();

    try std.testing.expectEqual(
        prepared.topology.trace_openings.len,
        session.context.uploads,
    );
    try std.testing.expect(!std.mem.allEqual(u8, &prepared.identity, 0));

    var cursor = transcript_controller.Cursor{
        .initialized = true,
        .next_step = schedule.operation_count - 1,
    };
    session.context.active_stage = .decommit;
    const route = try prepared.executeWith(
        FakeOps,
        &session,
        &fixture.plan,
        fixture.protocol,
        schedule,
        &cursor,
    );
    try std.testing.expect(cursor.complete(schedule));
    try std.testing.expectEqual(subject.State.complete, prepared.state);
    try route.validate(&fixture.plan, schedule, fixture.protocol);
    try std.testing.expectEqual(
        bindings.proof.bundle.address,
        route.transport.address,
    );
    try std.testing.expectEqual(
        fixture.plan.terminal_bundle.total_words,
        route.transport.len,
    );
    try std.testing.expectEqual(@as(usize, 1), session.query_draws);
    try std.testing.expectEqual(@as(u32, 38), session.query_step);
    try std.testing.expectEqual(
        bindings.decommit.raw_queries.address,
        session.query_destination,
    );
    try std.testing.expectEqual(@as(usize, 1), session.normalizes);
    try std.testing.expectEqual(
        prepared.topology.trace_openings.len,
        session.trace_prepares,
    );
    try std.testing.expectEqual(
        prepared.topology.trace_groups.len,
        session.trace_packs,
    );
    try std.testing.expectEqual(
        prepared.topology.trace_openings.len,
        session.trace_assemblies,
    );
    try std.testing.expectEqual(
        prepared.topology.fri_openings.len,
        session.fri_prepares,
    );
    try std.testing.expectEqual(
        prepared.topology.fri_openings.len,
        session.fri_assemblies,
    );
    try std.testing.expectEqual(@as(usize, 1), session.captures);
    try std.testing.expectEqual(
        bindings.decommit_assembly.address,
        session.capture_source,
    );
    try std.testing.expectEqual(
        bindings.proof.decommitment.address,
        session.capture_destination,
    );

    var wrong_schedule = schedule;
    wrong_schedule.schedule_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidTerminalRouteIdentity,
        route.validate(
            &fixture.plan,
            wrong_schedule,
            fixture.protocol,
        ),
    );
    try std.testing.expectError(
        error.InvalidDecommitControllerState,
        prepared.executeWith(
            FakeOps,
            &session,
            &fixture.plan,
            fixture.protocol,
            schedule,
            &cursor,
        ),
    );

    std.debug.print(
        "SN2 decommit controller: query_step={} groups={} records={} " ++
            "identity={s} route={s}\n",
        .{
            session.query_step,
            prepared.topology.trace_groups.len,
            prepared.topology.tree_count,
            std.fmt.bytesToHex(prepared.identity, .lower),
            std.fmt.bytesToHex(route.identity, .lower),
        },
    );
}

const FakeContext = struct {
    active_stage: telemetry.Stage,
    uploads: usize = 0,

    pub fn uploadSlice(
        self: *FakeContext,
        comptime T: type,
        destination: column.DeviceSlice(T),
        source: []const T,
    ) !void {
        if (self.active_stage != .ingress or
            destination.len != source.len or destination.address == 0)
        {
            return error.InvalidUpload;
        }
        self.uploads += 1;
    }
};

const FakeSession = struct {
    context: FakeContext,
    query_draws: usize = 0,
    query_step: u32 = 0,
    query_destination: usize = 0,
    normalizes: usize = 0,
    trace_prepares: usize = 0,
    trace_packs: usize = 0,
    trace_assemblies: usize = 0,
    fri_prepares: usize = 0,
    fri_assemblies: usize = 0,
    captures: usize = 0,
    capture_source: usize = 0,
    capture_destination: usize = 0,

    fn require(self: *FakeSession, stage: telemetry.Stage) !void {
        if (self.context.active_stage != stage)
            return error.StageOrderViolation;
    }
};

const FakeTranscript = struct {
    pub fn drawQueries(
        session: *FakeSession,
        _: common.Words,
        boundary: anytype,
        _: u32,
        output: common.Words,
        snapshot: common.Words,
    ) !void {
        try session.require(.decommit);
        if (!fixture_module.same(output, snapshot))
            return error.DetachedQuerySnapshot;
        session.query_draws += 1;
        session.query_step = boundary.expected_step;
        session.query_destination = output.address;
    }
};

const FakeDecommit = struct {
    pub fn normalizeQueries(
        session: *FakeSession,
        _: common.Words,
        _: u32,
        _: u32,
        _: common.Words,
        _: common.Words,
        _: common.Words,
    ) !void {
        try session.require(.decommit);
        session.normalizes += 1;
    }

    pub fn prepareTraceQueries(
        session: *FakeSession,
        _: common.Words,
        _: common.Words,
        source_log: u32,
        tree_log: u32,
        leaf_log: u32,
        _: u32,
        _: anytype,
    ) !void {
        try session.require(.decommit);
        if (source_log < tree_log or tree_log != leaf_log)
            return error.InvalidTraceProjection;
        session.trace_prepares += 1;
    }

    pub fn packTraceGroup(
        session: *FakeSession,
        _: u32,
        _: u32,
        _: u32,
        _: common.WordMatrix,
        _: common.Words,
        lifting_log: u32,
        _: common.Words,
        _: common.Words,
        _: common.Words,
    ) !void {
        try session.require(.decommit);
        if (lifting_log == 0) return error.InvalidTraceProjection;
        session.trace_packs += 1;
    }

    pub fn assembleTrace(
        session: *FakeSession,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: anytype,
    ) !void {
        try session.require(.decommit);
        session.trace_assemblies += 1;
    }

    pub fn prepareFriQueries(
        session: *FakeSession,
        _: common.Words,
        _: common.Words,
        _: u32,
        _: u32,
        _: u32,
        _: anytype,
    ) !void {
        try session.require(.decommit);
        session.fri_prepares += 1;
    }

    pub fn assembleFri(
        session: *FakeSession,
        _: u32,
        _: u32,
        _: anytype,
    ) !void {
        try session.require(.decommit);
        session.fri_assemblies += 1;
    }
};

const FakeCapture = struct {
    pub fn captureDecommitment(
        session: *FakeSession,
        views: anytype,
        source: common.Words,
    ) !void {
        try session.require(.decommit);
        if (source.len != views.proof.decommitment.len)
            return error.InvalidDecommitCapture;
        session.captures += 1;
        session.capture_source = source.address;
        session.capture_destination = views.proof.decommitment.address;
    }
};

const FakeOps = struct {
    pub const Transcript = FakeTranscript;
    pub const Decommit = FakeDecommit;
    pub const Capture = FakeCapture;
};
