//! Checked resident challenge-power expansion for Native constraints.

const field = @import("../../abi/field.zig");
const abi = @import("../../abi/stages/constraint_power.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
pub const max_power_count: usize = 510;

const stage = telemetry.Stage.constraint_evaluation;

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn expand(
            session: anytype,
            alpha: common.SecureFields,
            output: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            if (alpha.len != 1 or output.len == 0 or
                output.len > max_power_count)
            {
                return error.InvalidKernelDescriptor;
            }
            const alpha_value = try layout.resident(
                session,
                field.SecureField,
                alpha,
                1,
            );
            const output_values = try layout.resident(
                session,
                field.SecureField,
                output,
                output.len,
            );
            try layout.requireDisjoint(
                &.{output_values.range},
                &.{alpha_value.range},
            );
            const status = Api.stwo_constraint_expand_powers_on(
                @ptrCast(alpha_value.pointer),
                output_values.pointer,
                output.len,
                try common.count(output.len),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

test "constraint powers validate stage ownership range alias and capacity" {
    const TestApi = struct {
        var launches: u32 = 0;
        var last_stream: usize = 0;

        fn stwo_constraint_expand_powers_on(
            _: *const field.SecureField,
            _: [*]field.SecureField,
            output_capacity: usize,
            count: u32,
            stream: *anyopaque,
        ) c_int {
            if (output_capacity != @as(usize, count)) return 1;
            launches += 1;
            last_stream = @intFromPtr(stream);
            return 0;
        }
    };
    const Ops = OpsFor(TestApi);
    var session = TestSession{};
    const alpha = testSecure(0x1000, 1);
    const output = testSecure(0x1100, 4);

    try Ops.expand(&session, alpha, output);
    try @import("std").testing.expectEqual(@as(u32, 1), TestApi.launches);
    try @import("std").testing.expectEqual(
        @intFromPtr(session.context.stream),
        TestApi.last_stream,
    );
    try @import("std").testing.expectEqual(@as(u64, 1), session.launches);

    var foreign = output;
    foreign.owner += 1;
    try @import("std").testing.expectError(
        error.InvalidDeviceAddress,
        Ops.expand(&session, alpha, foreign),
    );
    var outside = output;
    outside.address = 0x1ff0;
    try @import("std").testing.expectError(
        error.InvalidDeviceAddress,
        Ops.expand(&session, alpha, outside),
    );
    var alias = output;
    alias.address = alpha.address;
    try @import("std").testing.expectError(
        error.OverlappingDeviceRange,
        Ops.expand(&session, alpha, alias),
    );
    var too_wide = output;
    too_wide.len = max_power_count + 1;
    try @import("std").testing.expectError(
        error.InvalidKernelDescriptor,
        Ops.expand(&session, alpha, too_wide),
    );
    session.context.active_stage = .oods;
    try @import("std").testing.expectError(
        error.StageOrderViolation,
        Ops.expand(&session, alpha, output),
    );
}

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn recordOrdinaryKernel(
        self: *TestSession,
        expected: telemetry.Stage,
        status: c_int,
    ) runtime_error.Error!void {
        if (expected != self.context.active_stage)
            return error.StageOrderViolation;
        try runtime_error.check(status);
        self.launches += 1;
    }
};

const TestContext = struct {
    active_stage: telemetry.Stage = stage,
    stream: *anyopaque = @ptrFromInt(0x3000),

    pub fn requireStage(
        self: *TestContext,
        expected: telemetry.Stage,
    ) runtime_error.Error!void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *TestContext,
        comptime F: type,
        slice: anytype,
        minimum: usize,
    ) runtime_error.Error![*]F {
        if (minimum == 0 or slice.len < minimum or
            slice.owner != 7 or slice.generation != 11 or
            slice.address % @alignOf(F) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        const std = @import("std");
        const bytes = std.math.mul(
            usize,
            minimum,
            @sizeOf(F),
        ) catch return error.SizeOverflow;
        const end = std.math.add(
            usize,
            slice.address,
            bytes,
        ) catch return error.SizeOverflow;
        if (slice.address < 0x1000 or end > 0x2000)
            return error.InvalidDeviceAddress;
        return @ptrFromInt(slice.address);
    }
};

fn testSecure(address: usize, len: usize) common.SecureFields {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}
