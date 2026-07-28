const std = @import("std");
const arena = @import(
    "../../../../backends/cuda/runtime/arena.zig",
);
const telemetry = @import(
    "../../../../backends/cuda/runtime/telemetry.zig",
);
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const fixed_bundle = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const semantic_authority = @import("stwo_cairo_frontend").proof_plan.semantic_authority;
const pcs_hooks = @import("../pcs_hooks.zig");
const resident_plan = @import("../resident_plan.zig");
const resident_test = @import("../resident_plan_test_support.zig");
const fixture = @import("../resident_plan_test.zig");
const subject = @import("controller.zig");

test "SN2 quotient controller binds exact topology and stage order" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    var fixed = try fixed_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed.deinit();
    const preprocessed_logs = try semantic_authority.preprocessedLogs(
        allocator,
        fixed,
    );
    defer allocator.free(preprocessed_logs);
    const protocol = try fixture.sn2Protocol(
        bundle,
        preprocessed_logs.len,
    );
    var program = try fixture.sn2Program(
        allocator,
        bundle,
        protocol,
        preprocessed_logs,
    );
    defer program.deinit(allocator);
    var plan = try resident_plan.Plan.init(
        allocator,
        program,
        protocol,
        bundle,
        try resident_test.geometry(program, bundle),
    );
    defer plan.deinit(allocator);

    const provider = Provider{ .plan = &plan };
    const bindings = try pcs_hooks.bind(
        provider,
        &plan,
        program,
        protocol,
    );
    var session = FakeSession.init(.ingress);
    var prepared = try subject.prepare(
        allocator,
        &session,
        &plan,
        bundle,
        program,
        protocol,
        bindings,
    );
    defer prepared.deinit();
    try std.testing.expectEqual(
        @as(usize, 6_342),
        prepared.topology.prepared_terms.len,
    );
    try std.testing.expectEqual(
        @as(usize, 19),
        prepared.groups.group_count,
    );
    try std.testing.expectEqual(
        @as(usize, 20_971_472),
        prepared.combine.partial_word_count,
    );
    try std.testing.expect(!std.mem.allEqual(
        u8,
        &prepared.identity,
        0,
    ));

    session.context.active_stage = .quotient;
    try prepared.executeWith(FakeOps, &session);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 1, 2, 3, 4 },
        session.steps[0..session.step_count],
    );
}

const Provider = struct {
    plan: *const resident_plan.Plan,

    pub fn slot(self: Provider, id: arena.SlotId) !@import(
        "../../../../backends/cuda/runtime/stages/common.zig",
    ).Words {
        var cursor: usize = 0;
        for (self.plan.slots) |descriptor| {
            cursor = std.mem.alignForward(
                usize,
                cursor,
                descriptor.alignment_words,
            );
            if (descriptor.id == id) {
                return .{
                    .address = 0x1_0000_0000 + cursor * @sizeOf(u32),
                    .len = descriptor.words,
                    .owner = 91,
                    .generation = 17,
                };
            }
            cursor = std.math.add(
                usize,
                cursor,
                descriptor.words,
            ) catch return error.SizeOverflow;
        }
        return error.ArenaSlotMissing;
    }
};

const FakeContext = struct {
    stream_storage: u8 = 0,
    stream: *anyopaque = undefined,
    active_stage: ?telemetry.Stage = null,

    fn init(stage: telemetry.Stage) FakeContext {
        var result = FakeContext{ .active_stage = stage };
        result.stream = &result.stream_storage;
        return result;
    }

    pub fn requireStage(
        self: *@This(),
        expected: telemetry.Stage,
    ) !void {
        if (self.active_stage != expected)
            return error.StageOrderViolation;
    }

    pub fn uploadSlice(
        self: *@This(),
        comptime T: type,
        destination: anytype,
        source: []const T,
    ) !void {
        try self.requireStage(.ingress);
        if (destination.owner != 91 or destination.len < source.len or
            destination.address == 0 or
            destination.address % @alignOf(T) != 0)
        {
            return error.InvalidDeviceAddress;
        }
    }
};

const FakeSession = struct {
    context: FakeContext,
    steps: [4]u8 = undefined,
    step_count: usize = 0,

    fn init(stage: telemetry.Stage) FakeSession {
        return .{ .context = FakeContext.init(stage) };
    }

    fn record(self: *@This(), step: u8) !void {
        if (self.step_count >= self.steps.len)
            return error.TooManyStages;
        self.steps[self.step_count] = step;
        self.step_count += 1;
    }
};

const FakeOps = struct {
    pub fn prepareTerms(
        session: *FakeSession,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
    ) !void {
        try session.record(1);
    }

    pub fn finalizeGroups(
        session: *FakeSession,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
    ) !void {
        try session.record(2);
    }

    pub fn accumulate(
        session: *FakeSession,
        _: anytype,
        _: anytype,
        _: anytype,
    ) !void {
        try session.record(3);
    }

    pub fn combine(
        session: *FakeSession,
        _: u32,
        _: u32,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
    ) !void {
        try session.record(4);
    }
};
