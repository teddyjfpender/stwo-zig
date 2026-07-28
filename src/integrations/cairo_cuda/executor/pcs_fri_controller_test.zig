const std = @import("std");
const field = @import("stwo_cuda_backend").abi.field;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const fixture_module = @import("pcs_controller_test_fixture.zig");
const pcs_hooks = @import("pcs_hooks.zig");
const subject = @import("pcs_fri_controller.zig");
const transcript_schedule = @import("transcript/schedule.zig");
const transcript_controller = @import("transcript/controller.zig");

const EventKind = enum { commit, mix, draw, fold, last };

const Event = struct {
    kind: EventKind,
    value: u32,
};

const FakeSession = struct {
    context: Context = .{},
    active_stage: telemetry.Stage = .ingress,
    events: [64]Event = undefined,
    event_count: usize = 0,
    captured_roots: usize = 0,
    captured_last: usize = 0,

    fn append(self: *FakeSession, kind: EventKind, value: u32) !void {
        if (self.event_count >= self.events.len)
            return error.TooManyFriEvents;
        self.events[self.event_count] = .{ .kind = kind, .value = value };
        self.event_count += 1;
    }
};

const Context = struct {
    active_stage: telemetry.Stage = .ingress,
    uploads: usize = 0,

    pub fn requireStage(
        self: *Context,
        stage: telemetry.Stage,
    ) !void {
        if (self.active_stage != stage)
            return error.StageOrderViolation;
    }

    pub fn uploadSlice(
        self: *Context,
        comptime F: type,
        destination: anytype,
        source: []const F,
    ) !void {
        if (self.active_stage != .ingress or
            destination.len != source.len or source.len == 0)
        {
            return error.InvalidKernelDescriptor;
        }
        self.uploads += 1;
    }
};

const FakeCommitment = struct {
    pub fn fri(
        session: *FakeSession,
        evaluation_size: u32,
        _: common.WordMatrix,
        hashes: common.Hashes,
        layers: []const field.MerkleLayerDescriptor,
    ) !common.Hashes {
        if (layers.len == 0 or
            layers[layers.len - 1].hash_count != 1)
        {
            return error.InvalidMerkleLayout;
        }
        try session.append(.commit, evaluation_size);
        return hashes.sub(
            @intCast(layers[layers.len - 1].offset_hashes),
            1,
        );
    }
};

const FakeFri = struct {
    pub fn foldLayer(
        session: *FakeSession,
        _: common.Words,
        layer: subject.Layer,
        _: bool,
        _: common.WordMatrix,
        alpha: common.SecureFields,
        destination: common.WordMatrix,
    ) !void {
        if (alpha.len != 1 or
            destination.column_stride_words !=
                layer.evaluation_size >>
                    @intCast(layer.fold_step))
        {
            return error.InvalidFoldBinding;
        }
        try session.append(.fold, layer.fold_step);
    }

    pub fn lastLayer(
        session: *FakeSession,
        _: common.Words,
        evaluation_stride: u32,
        log_size: u32,
        _: common.Words,
        log_degree_bound: u32,
        _: common.Words,
        degree_error: common.Words,
        _: common.Words,
    ) !void {
        if (evaluation_stride != @as(u32, 1) << @intCast(log_size) or
            degree_error.len != 1)
        {
            return error.InvalidLastLayer;
        }
        try session.append(.last, log_degree_bound);
    }
};

const FakeTranscript = struct {
    pub fn mixWords(
        session: *FakeSession,
        stage: telemetry.Stage,
        _: common.Words,
        boundary: anytype,
        source: common.Words,
        validate_m31: bool,
        snapshot: common.Words,
    ) !void {
        if (stage != .fri_commit or
            !same(source, snapshot) or
            validate_m31 != (boundary.expected_step == 36))
        {
            return error.InvalidTranscriptMix;
        }
        try session.append(.mix, boundary.expected_step);
    }

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
        if (stage != .fri_commit or felt_count != 1 or
            rejection_rounds != transcript_schedule.max_rejection_rounds or
            !same(output, snapshot))
        {
            return error.InvalidTranscriptDraw;
        }
        try session.append(.draw, boundary.expected_step);
    }
};

const FakeOps = struct {
    pub const Commitment = FakeCommitment;
    pub const Fri = FakeFri;
    pub const Transcript = FakeTranscript;
    pub const Capture = struct {
        pub fn captureFriRoot(
            session: *FakeSession,
            views: anytype,
            index: usize,
            root: common.Hashes,
        ) !void {
            if (root.len != 1 or
                index >= views.proof.fri_commitments.len / 8)
            {
                return error.InvalidFriCapture;
            }
            session.captured_roots += 1;
        }

        pub fn captureLastLayer(
            session: *FakeSession,
            views: anytype,
        ) !void {
            if (views.fri.last_transcript.len == 0)
                return error.InvalidFriCapture;
            session.captured_last += 1;
        }
    };
};

test "SN2 FRI controller executes every layer once in transcript order" {
    var fixture = try fixture_module.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const bindings = try pcs_hooks.bind(
        fixture_module.Provider{ .plan = &fixture.plan },
        &fixture.plan,
        fixture.program,
        fixture.protocol,
    );
    try std.testing.expect(bindings.fri_terminal_extent_matches);
    const schedule = try transcript_schedule.Schedule.init(
        fixture.program,
        fixture.protocol,
    );
    var session = FakeSession{};
    var prepared = try subject.prepare(
        std.testing.allocator,
        &session,
        &fixture.plan,
        fixture.program,
        fixture.protocol,
        bindings,
        schedule,
    );
    defer prepared.deinit();
    try std.testing.expectEqual(
        fixture.program.fri_layers.len,
        session.context.uploads,
    );
    const ingress_uploads = session.context.uploads;

    session.active_stage = .fri_commit;
    session.context.active_stage = .fri_commit;
    var cursor = transcript_controller.Cursor{
        .initialized = true,
        .next_step = 20,
    };
    try prepared.executeWith(
        FakeOps,
        &session,
        schedule,
        &cursor,
    );
    try std.testing.expectEqual(
        fixture.program.fri_layers.len,
        session.captured_roots,
    );
    try std.testing.expectEqual(@as(usize, 1), session.captured_last);
    try std.testing.expectEqual(
        ingress_uploads,
        session.context.uploads,
    );
    try std.testing.expectEqual(subject.State.complete, prepared.state);
    try std.testing.expectEqual(@as(u32, 37), cursor.next_step);

    var event: usize = 0;
    for (fixture.program.fri_layers, 0..) |layer, ordinal| {
        try expectEvent(
            session.events[event],
            .commit,
            @as(u32, 1) << @intCast(layer.evaluation_log_rows),
        );
        event += 1;
        try expectEvent(
            session.events[event],
            .mix,
            @intCast(20 + ordinal * 2),
        );
        event += 1;
        try expectEvent(
            session.events[event],
            .draw,
            @intCast(21 + ordinal * 2),
        );
        event += 1;
        try expectEvent(
            session.events[event],
            .fold,
            layer.fold_step,
        );
        event += 1;
    }
    try expectEvent(
        session.events[event],
        .last,
        fixture.protocol.log_last_layer_degree_bound,
    );
    event += 1;
    try expectEvent(session.events[event], .mix, 36);
    event += 1;
    try std.testing.expectEqual(event, session.event_count);
    try std.testing.expectError(
        error.InvalidFriControllerState,
        prepared.executeWith(
            FakeOps,
            &session,
            schedule,
            &cursor,
        ),
    );
}

test "FRI controller rejects topology and resident identity drift" {
    var fixture = try fixture_module.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const bindings = try pcs_hooks.bind(
        fixture_module.Provider{ .plan = &fixture.plan },
        &fixture.plan,
        fixture.program,
        fixture.protocol,
    );
    const schedule = try transcript_schedule.Schedule.init(
        fixture.program,
        fixture.protocol,
    );
    var session = FakeSession{};
    var prepared = try subject.prepare(
        std.testing.allocator,
        &session,
        &fixture.plan,
        fixture.program,
        fixture.protocol,
        bindings,
        schedule,
    );
    defer prepared.deinit();

    prepared.topology.layers[0].fold_step = 2;
    try std.testing.expectError(
        error.InvalidFriControllerIdentity,
        prepared.validate(schedule),
    );
    prepared.topology.layers[0].fold_step = 3;
    prepared.bindings.fri.layers[1]
        .coordinates.storage.generation += 1;
    try std.testing.expectError(
        error.InvalidFriControllerIdentity,
        prepared.validate(schedule),
    );
}

fn expectEvent(
    actual: Event,
    kind: EventKind,
    value: u32,
) !void {
    try std.testing.expectEqual(kind, actual.kind);
    try std.testing.expectEqual(value, actual.value);
}

fn same(left: anytype, right: @TypeOf(left)) bool {
    return left.address == right.address and left.len == right.len and
        left.owner == right.owner and
        left.generation == right.generation;
}
