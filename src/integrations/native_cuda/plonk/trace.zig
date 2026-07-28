//! CPU oracle boundary and CUDA recipe for the Native Plonk trace.

const std = @import("std");
const cpu_plonk = @import("../../../examples/plonk/input.zig");
const geometry_mod = @import("geometry.zig");
const indexed_recurrence =
    @import("stwo_cuda_backend").runtime.traces.indexed_recurrence;
const ir = @import("stwo_backend_contracts").proof_program;
const pcs = @import("stwo_core").pcs;

pub const Materialized = struct {
    geometry: geometry_mod.Geometry,
    prepared: cpu_plonk.PreparedInput,
    digest: ir.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        statement: cpu_plonk.Statement,
        protocol: pcs.PcsConfig,
    ) !Materialized {
        const geometry = try geometry_mod.admit(statement, protocol);
        var prepared = try cpu_plonk.prepare(allocator, statement);
        errdefer prepared.deinit(allocator);
        try validatePrepared(&prepared, geometry);
        return .{
            .geometry = geometry,
            .prepared = prepared,
            .digest = try digestPrepared(&prepared),
        };
    }

    pub fn deinit(self: *Materialized, allocator: std.mem.Allocator) void {
        self.prepared.deinit(allocator);
        self.* = undefined;
    }
};

pub fn digestPrepared(
    prepared: *const cpu_plonk.PreparedInput,
) !ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/native/plonk/materialized-trace-values/v1");
    hashInt(&hash, u32, prepared.request.log_n_rows);
    hashTree(
        &hash,
        0,
        prepared.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed,
    );
    hashTree(
        &hash,
        1,
        prepared.trace.main.columns orelse
            return error.PreparedInputConsumed,
    );
    var result: ir.Digest = undefined;
    hash.final(&result);
    return result;
}

fn validatePrepared(
    prepared: *const cpu_plonk.PreparedInput,
    geometry: geometry_mod.Geometry,
) !void {
    try prepared.trace.validate();
    if (!std.meta.eql(prepared.request, geometry.statement))
        return error.InvalidPreparedGeometry;
    const preprocessed = prepared.trace.preprocessed.columns orelse
        return error.PreparedInputConsumed;
    const main = prepared.trace.main.columns orelse
        return error.PreparedInputConsumed;
    if (preprocessed.len != geometry_mod.preprocessed_columns or
        main.len != geometry_mod.main_columns or
        prepared.trace.committed_columns != geometry.traceColumnCount() or
        prepared.trace.committed_cells != geometry.trace_elements)
    {
        return error.InvalidPreparedGeometry;
    }
}

fn hashTree(
    hash: *std.crypto.hash.sha2.Sha256,
    role: u32,
    columns: anytype,
) void {
    hashInt(hash, u32, role);
    hashInt(hash, u64, @intCast(columns.len));
    for (columns, 0..) |column, ordinal| {
        hashInt(hash, u64, @intCast(ordinal));
        hashInt(hash, u32, column.log_size);
        hashInt(hash, u64, @intCast(column.values.len));
        for (column.values) |value| hashInt(hash, u32, value.toU32());
    }
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

pub const recipe = indexed_recurrence.Recipe{
    .index_base = 0,
    .index_step = 1,
    .preprocessed_constant = 1,
    .recurrence_seed0 = 1,
    .recurrence_seed1 = 1,
    .selector_default = 1,
    .selector_last = 0,
    .selector_penultimate = 1,
};

pub fn prepare(
    session: anytype,
    destinations: indexed_recurrence.Destinations,
    statement: cpu_plonk.Statement,
) !indexed_recurrence.PreparedLaunch {
    try cpu_plonk.validate(statement);
    return indexed_recurrence.prepare(
        session,
        destinations,
        .{ .log_n_rows = statement.log_n_rows },
        recipe,
    );
}

pub fn generate(
    session: anytype,
    destinations: indexed_recurrence.Destinations,
    statement: cpu_plonk.Statement,
) !void {
    var launch = try prepare(session, destinations, statement);
    try launch.launch(session);
}

test "Plonk binding contributes only statement geometry and AIR recipe" {
    var session = TestSession{};
    try generate(
        &session,
        .{
            .preprocessed = testMatrix(0x1000, 32),
            .main = testMatrix(0x4000, 32),
        },
        .{ .log_n_rows = 5 },
    );
    try std.testing.expectEqual(@as(u64, 1), session.launches);
}

test "materialized Plonk trace is exactly the CPU oracle trace" {
    const allocator = std.testing.allocator;
    const statement = cpu_plonk.Statement{ .log_n_rows = 7 };
    var materialized = try Materialized.init(
        allocator,
        statement,
        pcs.PcsConfig.default(),
    );
    defer materialized.deinit(allocator);
    var oracle = try cpu_plonk.prepare(allocator, statement);
    defer oracle.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &(try digestPrepared(&oracle)),
        &materialized.digest,
    );
}

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn launchKernel(
        self: *TestSession,
        kernel: @import("stwo_cuda_backend").runtime.kernel.Kernel,
        arguments: []const ?*anyopaque,
    ) @import("stwo_cuda_backend").runtime.runtime_error.Error!void {
        try kernel.validate();
        if (arguments.len != indexed_recurrence.argument_count)
            return error.ArgumentCountMismatch;
        self.launches += 1;
    }
};

const TestContext = struct {
    active_stage: @import("stwo_cuda_backend").runtime.telemetry.Stage = .trace_generation,

    pub fn requireStage(
        self: *TestContext,
        expected: @import("stwo_cuda_backend").runtime.telemetry.Stage,
    ) @import("stwo_cuda_backend").runtime.runtime_error.Error!void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *TestContext,
        comptime F: type,
        slice: anytype,
        minimum: usize,
    ) @import("stwo_cuda_backend").runtime.runtime_error.Error![*]F {
        if (minimum == 0 or slice.len < minimum or
            slice.owner != 7 or slice.generation != 11)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }
};

fn testMatrix(address: usize, stride: usize) @import("stwo_cuda_backend").runtime.stages.common.WordMatrix {
    return .{
        .storage = .{
            .address = address,
            .len = stride * indexed_recurrence.column_count,
            .owner = 7,
            .generation = 11,
        },
        .column_stride_words = stride,
    };
}
