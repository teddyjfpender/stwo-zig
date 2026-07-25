const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
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
const subject = @import("pcs_oods_controller.zig");

test "SN2 OODS controller derives challenges only through transcript" {
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
        fixture.bundle,
        fixture.program,
        fixture.protocol,
        bindings,
        schedule,
    );
    defer prepared.deinit();

    try std.testing.expectEqual(@as(usize, 3), session.context.uploads);
    try std.testing.expectEqual(
        @as(usize, 6_110),
        prepared.bound.oods.sampled_values.len,
    );
    try std.testing.expectEqual(
        @as(usize, 365),
        prepared.bound.batches.len,
    );
    try std.testing.expect(!std.mem.allEqual(u8, &prepared.identity, 0));

    var cursor = transcript_controller.Cursor{
        .initialized = true,
        .next_step = 17,
    };
    session.context.active_stage = .constraint_evaluation;
    try prepared.drawParameterWith(
        FakeTranscript,
        &session,
        schedule,
        &cursor,
    );
    try std.testing.expectEqual(@as(u32, 18), cursor.next_step);
    try std.testing.expectEqual(
        prepared.bound.oods.parameter.address,
        session.draw_destinations[0],
    );

    session.context.active_stage = .oods;
    try prepared.executeWith(
        FakeOps,
        &session,
        schedule,
        &cursor,
    );
    try std.testing.expectEqual(subject.State.complete, prepared.state);
    try std.testing.expectEqual(@as(u32, 20), cursor.next_step);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 17, 18, 19 },
        session.transcript_steps[0..session.transcript_count],
    );
    try std.testing.expectEqual(
        prepared.quotient_challenge.address,
        session.draw_destinations[1],
    );
    try std.testing.expectEqual(
        prepared.bound.batches.len,
        session.derive_calls,
    );
    try std.testing.expectEqual(
        prepared.bound.batches.len,
        session.first_calls,
    );
    try std.testing.expectEqual(
        prepared.bound.batches.len,
        session.store_calls,
    );
    try std.testing.expect(session.reduce_calls != 0);
    try std.testing.expectEqual(@as(usize, 1), session.capture_calls);
    try std.testing.expectEqual(
        prepared.bound.oods.sampled_values.address,
        session.captured_source,
    );
    try std.testing.expectEqual(
        prepared.proof.sampled_values.address,
        session.captured_destination,
    );

    var wrong_schedule = schedule;
    wrong_schedule.schedule_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidOodsControllerIdentity,
        prepared.validate(wrong_schedule),
    );
    try std.testing.expectError(
        error.InvalidOodsControllerState,
        prepared.executeWith(
            FakeOps,
            &session,
            schedule,
            &cursor,
        ),
    );

    std.debug.print(
        "SN2 OODS controller: batches={} transcript=17/18/19 " ++
            "identity={s}\n",
        .{
            prepared.bound.batches.len,
            std.fmt.bytesToHex(prepared.identity, .lower),
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
    transcript_steps: [3]u32 = undefined,
    transcript_count: usize = 0,
    draw_destinations: [2]usize = undefined,
    draw_count: usize = 0,
    derive_calls: usize = 0,
    first_calls: usize = 0,
    reduce_calls: usize = 0,
    store_calls: usize = 0,
    capture_calls: usize = 0,
    captured_source: usize = 0,
    captured_destination: usize = 0,

    fn recordTranscript(self: *FakeSession, step: u32) !void {
        if (self.transcript_count >= self.transcript_steps.len)
            return error.TooManyTranscriptCalls;
        self.transcript_steps[self.transcript_count] = step;
        self.transcript_count += 1;
    }

    fn require(self: *FakeSession, stage: telemetry.Stage) !void {
        if (self.context.active_stage != stage)
            return error.StageOrderViolation;
    }
};

const FakeTranscript = struct {
    pub fn drawSecure(
        session: *FakeSession,
        stage: telemetry.Stage,
        _: common.Words,
        boundary: anytype,
        felt_count: u32,
        rejection_rounds: u32,
        output: common.SecureFields,
        snapshot: common.SecureFields,
    ) !void {
        try session.require(stage);
        if (felt_count != 1 or
            rejection_rounds != transcript_schedule.max_rejection_rounds or
            !fixture_module.same(output, snapshot) or
            session.draw_count >= session.draw_destinations.len)
        {
            return error.InvalidTranscriptDraw;
        }
        session.draw_destinations[session.draw_count] = output.address;
        session.draw_count += 1;
        try session.recordTranscript(boundary.expected_step);
    }

    pub fn mixWords(
        session: *FakeSession,
        stage: telemetry.Stage,
        _: common.Words,
        boundary: anytype,
        source: common.Words,
        validate_m31: bool,
        snapshot: common.Words,
    ) !void {
        try session.require(stage);
        if (!validate_m31 or !fixture_module.same(source, snapshot))
            return error.InvalidTranscriptMix;
        try session.recordTranscript(boundary.expected_step);
    }
};

const FakeOods = struct {
    pub fn derivePoints(
        session: *FakeSession,
        _: common.SecureFields,
        _: column.DeviceSlice(field.CirclePointBaseField),
        _: anytype,
        _: u32,
        _: column.DeviceSlice(field.SecureCirclePoint),
        _: column.DeviceSlice(field.SecureCirclePoint),
        _: common.SecureFields,
    ) !void {
        try session.require(.oods);
        session.derive_calls += 1;
    }

    pub fn evaluateFirst(
        session: *FakeSession,
        _: common.WordMatrix,
        _: u32,
        _: common.SecureFields,
        _: common.SecureFields,
    ) !void {
        try session.require(.oods);
        session.first_calls += 1;
    }

    pub fn reduce(
        session: *FakeSession,
        _: common.SecureFields,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: common.SecureFields,
        _: common.SecureFields,
    ) !void {
        try session.require(.oods);
        session.reduce_calls += 1;
    }

    pub fn storeResults(
        session: *FakeSession,
        _: common.SecureFields,
        _: u32,
        _: anytype,
        _: common.SecureFields,
    ) !void {
        try session.require(.oods);
        session.store_calls += 1;
    }
};

const FakeCapture = struct {
    pub fn captureSampledValues(
        session: *FakeSession,
        views: anytype,
    ) !void {
        try session.require(.oods);
        const source = try views.oods.sampled_values.cast(u32);
        if (source.len != views.proof.sampled_values.len)
            return error.InvalidCapture;
        session.capture_calls += 1;
        session.captured_source = source.address;
        session.captured_destination = views.proof.sampled_values.address;
    }
};

const FakeOps = struct {
    pub const Oods = FakeOods;
    pub const Transcript = FakeTranscript;
    pub const Capture = FakeCapture;
};
