//! Strict-AOT launch binding for one generated Cairo constraint placement.

const std = @import("std");
const abi = @import("../../abi/stages/cairo_eval.zig");
const schema = @import("../../abi/schema.zig");
const column = @import("../column.zig");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const Args = abi.Args;
pub const Bounds = abi.Bounds;
pub const ExtSourceDescriptor = abi.ExtSourceDescriptor;

pub const ParameterLayout = struct {
    descriptors: u64,
    descriptor_count: u32,
    z: u64,
    alpha_powers: u64,
    alpha_power_count: u32,
    claimed_sums: u64,
    claimed_sum_count: u32,
    output: u64,
    output_words: u64,

    pub fn validate(self: ParameterLayout, arena_words: u64) !void {
        if (arena_words == 0 or
            self.descriptor_count == 0 or
            self.alpha_power_count == 0 or
            self.claimed_sum_count == 0 or
            self.output_words !=
                @as(u64, self.descriptor_count) * 4)
        {
            return error.InvalidCairoEvalArgs;
        }
        try range(
            self.descriptors,
            @as(u64, self.descriptor_count) *
                (@sizeOf(ExtSourceDescriptor) / @sizeOf(u32)),
            arena_words,
        );
        try range(self.z, 4, arena_words);
        try range(
            self.alpha_powers,
            @as(u64, self.alpha_power_count) * 4,
            arena_words,
        );
        try range(
            self.claimed_sums,
            @as(u64, self.claimed_sum_count) * 4,
            arena_words,
        );
        try range(self.output, self.output_words, arena_words);
    }
};

pub const Product = struct {
    cache_key: u64,
    kernel_name: [:0]const u8,
    args: Args,
    bounds: Bounds,
};

pub const PreparedLaunch = struct {
    kernel: kernel_module.Kernel,
    arguments: Arguments,

    pub fn launch(
        self: *PreparedLaunch,
        session: anytype,
    ) runtime_error.Error!void {
        var pointers = self.arguments.pointers();
        try session.launchKernel(self.kernel, &pointers);
    }
};

const Arguments = struct {
    arena: [*]u32,
    arena_words: u64,
    args: [*]const Args,

    fn pointers(self: *Arguments) [abi.argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.arena),
            @ptrCast(&self.arena_words),
            @ptrCast(&self.args),
        };
    }
};

pub fn materializeParameters(
    session: anytype,
    arena: common.Words,
    parameters: ParameterLayout,
) runtime_error.Error!void {
    try common.requireStage(session, .constraint_evaluation);
    parameters.validate(arena.len) catch
        return error.InvalidKernelDescriptor;
    const arena_view = try layout.resident(
        session,
        u32,
        arena,
        arena.len,
    );
    var launches: u32 = 0;
    const status = abi.stwo_cairo_eval_materialize_params_on(
        arena_view.pointer,
        @intCast(arena.len),
        parameters.descriptors,
        parameters.descriptor_count,
        parameters.z,
        parameters.alpha_powers,
        parameters.alpha_power_count,
        parameters.claimed_sums,
        parameters.claimed_sum_count,
        parameters.output,
        parameters.output_words,
        session.context.stream,
        &launches,
    );
    try common.recordMany(
        session,
        .constraint_evaluation,
        status,
        launches,
    );
}

/// Seals the exact arena base and one already-uploaded argument record while
/// ingress still owns all host-derived metadata.
pub fn prepare(
    session: anytype,
    product: Product,
    arena: common.Words,
    device_args: column.DeviceSlice(Args),
) runtime_error.Error!PreparedLaunch {
    try common.requireStage(session, .ingress);
    product.args.validate(product.bounds) catch
        return error.InvalidKernelDescriptor;
    if (product.cache_key == 0 or
        product.kernel_name.len == 0 or
        product.bounds.arena_words != arena.len or
        device_args.len != 1 or
        arena.owner != device_args.owner or
        arena.generation != device_args.generation)
    {
        return error.InvalidKernelDescriptor;
    }
    const arena_view = try layout.resident(
        session,
        u32,
        arena,
        arena.len,
    );
    const args_view = try layout.resident(
        session,
        Args,
        device_args,
        1,
    );
    if (args_view.range.start < arena_view.range.start or
        args_view.range.end > arena_view.range.end)
    {
        return error.InvalidKernelDescriptor;
    }
    const grid_x = std.math.divCeil(
        u32,
        product.args.row_count,
        abi.launch_block,
    ) catch return error.InvalidKernelDescriptor;
    const kernel = kernel_module.Kernel{
        .stage = .constraint_evaluation,
        .abi_schema = schema.KernelSchema.cairo_eval_part_v1,
        .cache_key = product.cache_key,
        .name = product.kernel_name,
        .grid = .{ grid_x, 1, 1 },
        .block = .{ abi.launch_block, 1, 1 },
        .argument_count = abi.argument_count,
    };
    try kernel.validate();
    return .{
        .kernel = kernel,
        .arguments = .{
            .arena = arena_view.pointer,
            .arena_words = @intCast(arena.len),
            .args = args_view.pointer,
        },
    };
}

test "Cairo eval placement seals one unified arena and launches at constraint stage" {
    var session = TestSession{};
    const arena = testSlice(u32, 0x1000, 512);
    const device_args = testSlice(Args, 0x1400, 1);
    const args = testArgs();
    var prepared = try prepare(
        &session,
        .{
            .cache_key = 0x1234,
            .kernel_name = "stwo_cairo_cuda_eval_v1_test",
            .args = args,
            .bounds = testBounds(),
        },
        arena,
        device_args,
    );
    session.context.active_stage = .constraint_evaluation;
    try prepared.launch(&session);
    try std.testing.expectEqual(@as(u64, 1), session.launches);
    try std.testing.expectEqual(
        schema.KernelSchema.cairo_eval_part_v1,
        session.last_schema,
    );

    session.context.active_stage = .ingress;
    var foreign = device_args;
    foreign.generation += 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(
            &session,
            .{
                .cache_key = 0x1234,
                .kernel_name = "stwo_cairo_cuda_eval_v1_test",
                .args = args,
                .bounds = testBounds(),
            },
            arena,
            foreign,
        ),
    );
}

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,
    last_schema: schema.KernelSchema = .ordinary_constraint_v1,

    pub fn launchKernel(
        self: *@This(),
        kernel: kernel_module.Kernel,
        arguments: []const ?*anyopaque,
    ) runtime_error.Error!void {
        try kernel.validate();
        if (self.context.active_stage != kernel.stage)
            return error.StageOrderViolation;
        if (arguments.len != abi.argument_count)
            return error.ArgumentCountMismatch;
        self.launches += 1;
        self.last_schema = kernel.abi_schema;
    }
};

const TestContext = struct {
    active_stage: telemetry.Stage = .ingress,
    stream: *anyopaque = @ptrFromInt(0x8000),

    pub fn requireStage(
        self: *@This(),
        expected: telemetry.Stage,
    ) runtime_error.Error!void {
        if (self.active_stage != expected)
            return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *@This(),
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
        return @ptrFromInt(slice.address);
    }
};

fn testSlice(
    comptime F: type,
    address: usize,
    len: usize,
) column.DeviceSlice(F) {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}

fn testArgs() Args {
    return .{
        .trace_offsets = 8,
        .interaction_offsets = 16,
        .base_params = 0,
        .ext_params = 32,
        .random_coeffs = 64,
        .denom_inv = 128,
        .coord_0 = 256,
        .coord_1 = 272,
        .coord_2 = 288,
        .coord_3 = 304,
        .row_count = 16,
        .trace_log_size = 3,
        .domain_log_size = 3,
        .rc_base = 4,
    };
}

fn testBounds() Bounds {
    return .{
        .arena_words = 512,
        .trace_offset_count = 4,
        .base_param_count = 0,
        .ext_param_count = 2,
        .random_constraint_count = 8,
        .denominator_count = 2,
        .rc_count = 3,
    };
}

fn range(offset: u64, count: u64, arena_words: u64) !void {
    const end = std.math.add(u64, offset, count) catch
        return error.InvalidCairoEvalArgs;
    if (count == 0 or offset >= arena_words or end > arena_words)
        return error.InvalidCairoEvalArgs;
}

test "Cairo eval parameter layout binds every dynamic source to one arena" {
    const parameters = ParameterLayout{
        .descriptors = 8,
        .descriptor_count = 3,
        .z = 32,
        .alpha_powers = 36,
        .alpha_power_count = 4,
        .claimed_sums = 52,
        .claimed_sum_count = 2,
        .output = 60,
        .output_words = 12,
    };
    try parameters.validate(72);
    var forged = parameters;
    forged.output_words -= 1;
    try std.testing.expectError(
        error.InvalidCairoEvalArgs,
        forged.validate(72),
    );
}
