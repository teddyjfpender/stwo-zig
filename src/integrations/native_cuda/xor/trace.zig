//! CPU-authoritative materialization boundary for the Native XOR trace.

const std = @import("std");
const cpu_xor = @import("stwo_native_examples").xor;
const geometry_mod = @import("geometry.zig");
const ir = @import("stwo_backend_contracts").proof_program;
const pcs = @import("stwo_core").pcs;

pub const Materialized = struct {
    geometry: geometry_mod.Geometry,
    prepared: cpu_xor.PreparedInput,
    digest: ir.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        statement: cpu_xor.Statement,
        protocol: pcs.PcsConfig,
    ) !Materialized {
        const geometry = try geometry_mod.admit(statement, protocol);
        var prepared = try cpu_xor.prepareInput(allocator, statement);
        errdefer prepared.deinit(allocator);
        try validate(&prepared, geometry);
        return .{
            .geometry = geometry,
            .digest = try digestPrepared(&prepared),
            .prepared = prepared,
        };
    }

    pub fn deinit(self: *Materialized, allocator: std.mem.Allocator) void {
        self.prepared.deinit(allocator);
        self.* = undefined;
    }
};

pub fn digestPrepared(prepared: *const cpu_xor.PreparedInput) !ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/native/xor/materialized-trace-values/v1");
    hashInt(&hash, u32, prepared.request.log_size);
    hashInt(&hash, u32, prepared.request.log_step);
    hashInt(&hash, u64, @intCast(prepared.request.offset));
    try hashTree(
        &hash,
        0,
        prepared.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed,
    );
    try hashTree(
        &hash,
        1,
        prepared.trace.main.columns orelse return error.PreparedInputConsumed,
    );
    var result: ir.Digest = undefined;
    hash.final(&result);
    return result;
}

fn validate(
    prepared: *const cpu_xor.PreparedInput,
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
        prepared.trace.committed_columns !=
            geometry_mod.preprocessed_columns + geometry_mod.main_columns or
        prepared.trace.committed_cells !=
            geometry.preprocessed_cells + geometry.main_cells)
    {
        return error.InvalidPreparedGeometry;
    }
}

fn hashTree(
    hash: *std.crypto.hash.sha2.Sha256,
    role: u32,
    columns: anytype,
) !void {
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

test "materialized XOR trace is exactly the CPU example trace" {
    const allocator = std.testing.allocator;
    const statement = cpu_xor.Statement{
        .log_size = 7,
        .log_step = 3,
        .offset = 5,
    };
    var materialized = try Materialized.init(
        allocator,
        statement,
        pcs.PcsConfig.default(),
    );
    defer materialized.deinit(allocator);
    var cpu = try cpu_xor.prepareInput(allocator, statement);
    defer cpu.deinit(allocator);

    const materialized_trees = .{
        materialized.prepared.trace.preprocessed.columns.?,
        materialized.prepared.trace.main.columns.?,
    };
    const cpu_trees = .{
        cpu.trace.preprocessed.columns.?,
        cpu.trace.main.columns.?,
    };
    inline for (materialized_trees, cpu_trees) |actual, expected| {
        try std.testing.expectEqual(expected.len, actual.len);
        for (actual, expected) |actual_column, expected_column| {
            try std.testing.expectEqual(expected_column.log_size, actual_column.log_size);
            try std.testing.expectEqualSlices(
                @TypeOf(expected_column.values[0]),
                expected_column.values,
                actual_column.values,
            );
        }
    }
    try std.testing.expectEqualSlices(
        u8,
        &(try digestPrepared(&cpu)),
        &materialized.digest,
    );
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected,
        "6d71c9e034f6ea47660d075ed4489fc9314d4f49f8b4b54f627ce0a5f29e8493",
    );
    try std.testing.expectEqualSlices(u8, &expected, &materialized.digest);
}

test "materialized XOR identity changes with public trace inputs" {
    const allocator = std.testing.allocator;
    var first = try Materialized.init(
        allocator,
        .{ .log_size = 7, .log_step = 3, .offset = 5 },
        pcs.PcsConfig.default(),
    );
    defer first.deinit(allocator);
    var second = try Materialized.init(
        allocator,
        .{ .log_size = 7, .log_step = 3, .offset = 6 },
        pcs.PcsConfig.default(),
    );
    defer second.deinit(allocator);
    try std.testing.expect(!std.mem.eql(u8, &first.digest, &second.digest));
}
