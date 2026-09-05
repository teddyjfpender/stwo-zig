//! Exact diagnostic parity for Metal's first FRI quotient column.
//!
//! Metal borrows raw committed columns to reuse proof-owned device buffers.
//! This owner independently reconstructs the ordinary CPU direct-column plan
//! from those same inputs and compares every output word. It is process-local
//! diagnostics only and is never mixed into a transcript or durable codec.

const std = @import("std");

const M31 = @import("stwo_core").fields.m31.M31;
const quotient_ops = @import("stwo_prover_engine").pcs.quotient_ops;
const tile_executor = @import("stwo_prover_engine").pcs.quotient_tile_executor;
const tile_sink = @import("stwo_prover_engine").pcs.quotient_tile_sink;
const quotients = @import("stwo_core").pcs.quotients;

pub const ENV_NAME = "STWO_ZIG_METAL_QUOTIENT_PARITY";
pub const SCHEMA_VERSION: u16 = 1;
pub const COORDINATE_COUNT: usize = 4;

pub const MismatchV1 = struct {
    row: usize,
    coordinate: u8,
    expected: M31,
    actual: M31,
};

pub const ReceiptV1 = struct {
    schema_version: u16 = SCHEMA_VERSION,
    lifting_log_size: u32,
    row_count: usize,
    compared_values: u64,
    expected_sha256: [32]u8,
    actual_sha256: [32]u8,

    pub fn validate(self: ReceiptV1) !void {
        if (self.lifting_log_size >= @bitSizeOf(usize))
            return error.InvalidMetalQuotientParityReceipt;
        const expected_rows = @as(usize, 1) << @intCast(self.lifting_log_size);
        const expected_values = std.math.mul(
            u64,
            @intCast(self.row_count),
            @as(u64, COORDINATE_COUNT),
        ) catch return error.InvalidMetalQuotientParityReceipt;
        if (self.schema_version != SCHEMA_VERSION or
            self.row_count != expected_rows or
            self.compared_values != expected_values or
            !std.mem.eql(u8, &self.expected_sha256, &self.actual_sha256) or
            std.mem.allEqual(u8, &self.actual_sha256, 0))
        {
            return error.InvalidMetalQuotientParityReceipt;
        }
    }
};

pub const ResultV1 = union(enum) {
    exact: ReceiptV1,
    mismatch: MismatchV1,
};

pub fn enabled() bool {
    return std.process.hasEnvVarConstant(ENV_NAME);
}

/// Recomputes the entire raw-provider output with the ordinary CPU quotient
/// formula. Marking every active input potentially nonzero only disables a
/// CPU planning optimization; it cannot change the field result.
pub fn compareRawProviderAgainstCpu(
    allocator: std.mem.Allocator,
    provider: *const quotient_ops.LazyQuotientProvider,
    actual: anytype,
) !ResultV1 {
    if (provider.input_mode != .raw_backend or
        provider.raw_columns.len == 0 or
        actual.len() != provider.domain_size)
    {
        return error.InvalidMetalQuotientParityInput;
    }
    inline for (0..COORDINATE_COUNT) |coordinate| {
        if (actual.columns[coordinate].len != provider.domain_size)
            return error.InvalidMetalQuotientParityInput;
    }

    const potentially_nonzero = try allocator.alloc(bool, provider.raw_columns.len);
    defer allocator.free(potentially_nonzero);
    @memset(potentially_nonzero, true);
    var direct = try tile_executor.buildDirectContributionPlan(
        allocator,
        provider.raw_columns,
        provider.prepared.contribution_plan.active_column_indices,
        provider.prepared.contribution_plan.ranges,
        potentially_nonzero,
        provider.lifting_log_size,
        null,
    );
    defer direct.deinit(allocator);

    var workspace = try quotients.RowQuotientWorkspace.init(
        allocator,
        provider.prepared.sample_batches,
    );
    defer workspace.deinit(allocator);
    const requested_rows = @min(
        provider.domain_size,
        tile_sink.DEFAULT_TILE_ROWS,
    );
    var scratch = try tile_executor.initScratchOrScalarFallback(
        allocator,
        provider.prepared.sample_batches.len,
        requested_rows,
        provider.domain_size,
    );
    defer if (scratch) |*value| value.deinit(allocator);

    const expected_storage = try allocator.alloc(
        M31,
        try std.math.mul(usize, COORDINATE_COUNT, requested_rows),
    );
    defer allocator.free(expected_storage);
    var expected_columns: [COORDINATE_COUNT][]M31 = undefined;
    inline for (0..COORDINATE_COUNT) |coordinate| {
        expected_columns[coordinate] = expected_storage[coordinate * requested_rows ..][0..requested_rows];
    }

    var expected_hash = std.crypto.hash.sha2.Sha256.init(.{});
    var actual_hash = std.crypto.hash.sha2.Sha256.init(.{});
    var start: usize = 0;
    while (start < provider.domain_size) {
        const count = @min(requested_rows, provider.domain_size - start);
        var output: [COORDINATE_COUNT][]M31 = undefined;
        inline for (0..COORDINATE_COUNT) |coordinate| {
            output[coordinate] = expected_columns[coordinate][0..count];
        }
        var work = tile_executor.Work{
            .out_columns = output,
            .start = start,
            .end = start + count,
            .output_start = start,
            .workspace = &workspace,
            .scratch = if (scratch) |*value| value else null,
            .domain = provider.domain,
            .column_views = direct.views,
            .contribution_ranges = direct.ranges,
            .contributions = provider.prepared.contribution_plan.contributions,
            .quotient_constants = &provider.prepared.quotient_constants,
            .lifting_log_size = provider.lifting_log_size,
        };
        try tile_executor.execute(&work);

        for (0..count) |local_row| {
            const row = start + local_row;
            inline for (0..COORDINATE_COUNT) |coordinate| {
                const expected = output[coordinate][local_row];
                const observed = actual.columns[coordinate][row];
                mixM31(&expected_hash, expected);
                mixM31(&actual_hash, observed);
                if (!expected.eql(observed)) return .{ .mismatch = .{
                    .row = row,
                    .coordinate = @intCast(coordinate),
                    .expected = expected,
                    .actual = observed,
                } };
            }
        }
        start += count;
    }

    var expected_sha256: [32]u8 = undefined;
    var actual_sha256: [32]u8 = undefined;
    expected_hash.final(&expected_sha256);
    actual_hash.final(&actual_sha256);
    const receipt = ReceiptV1{
        .lifting_log_size = provider.lifting_log_size,
        .row_count = provider.domain_size,
        .compared_values = try std.math.mul(
            u64,
            @intCast(provider.domain_size),
            @as(u64, COORDINATE_COUNT),
        ),
        .expected_sha256 = expected_sha256,
        .actual_sha256 = actual_sha256,
    };
    try receipt.validate();
    return .{ .exact = receipt };
}

fn mixM31(hash: *std.crypto.hash.sha2.Sha256, value: M31) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value.v, .little);
    hash.update(&bytes);
}
