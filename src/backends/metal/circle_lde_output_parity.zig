//! Diagnostic equivalence owner for Metal's combined circle IFFT + LDE path.
//!
//! The retained Stage101 main tree is wider than a `u32` word address space,
//! so Metal splits one logical 455-column transform into rebased dispatches.
//! A capture is taken before those dispatches can overwrite an adopted source
//! arena.  After the batch completes, this module independently applies the
//! ordinary CPU transforms and compares every coefficient and extended-domain
//! value for the columns bordering the addressability split.
//!
//! This evidence is process-local diagnostics only.  It is never mixed into a
//! transcript, proof, or durable artifact.

const std = @import("std");

const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const M31 = core.fields.m31.M31;
const CircleDomain = core.poly.circle.domain.CircleDomain;
const TwiddleTree = prover.poly.twiddles.TwiddleTree([]const M31);

pub const ENV_NAME = "STWO_ZIG_METAL_RETAINED_LDE_PARITY";
pub const SCHEMA_VERSION: u16 = 1;

const boundary_positions = [_]usize{ 0, 254, 255, 256, 339, 444 };

pub const RouteV1 = enum(u8) {
    monolithic = 1,
    u32_rebased = 2,
};

pub const PhaseV1 = enum(u8) {
    coefficient = 1,
    extended_evaluation = 2,
};

pub const MismatchV1 = struct {
    group_index: usize,
    group_column_index: usize,
    phase: PhaseV1,
    row: usize,
    expected: M31,
    actual: M31,
};

pub const ReceiptV1 = struct {
    schema_version: u16 = SCHEMA_VERSION,
    group_count: usize,
    rebased_group_count: usize,
    dispatch_count: usize,
    selected_column_count: usize,
    coefficient_values: u64,
    extended_values: u64,
    expected_sha256: [32]u8,
    actual_sha256: [32]u8,

    pub fn validate(self: ReceiptV1) !void {
        if (self.schema_version != SCHEMA_VERSION or
            self.group_count == 0 or
            self.rebased_group_count > self.group_count or
            self.dispatch_count < self.group_count or
            self.selected_column_count == 0 or
            self.coefficient_values == 0 or
            self.extended_values <= self.coefficient_values or
            !std.mem.eql(u8, &self.expected_sha256, &self.actual_sha256) or
            std.mem.allEqual(u8, &self.actual_sha256, 0))
        {
            return error.InvalidMetalCircleLdeParityReceipt;
        }
    }
};

pub const ResultV1 = union(enum) {
    exact: ReceiptV1,
    mismatch: MismatchV1,
};

const SelectedColumnV1 = struct {
    group_column_index: usize,
    expected_coefficients: []M31,
    actual_coefficients: []const M31,
    actual_extended: []const M31,

    fn deinit(self: *SelectedColumnV1, allocator: std.mem.Allocator) void {
        allocator.free(self.expected_coefficients);
        self.* = undefined;
    }
};

pub const GroupCaptureV1 = struct {
    group_column_count: usize,
    base_domain: CircleDomain,
    extended_domain: CircleDomain,
    base_twiddles: TwiddleTree,
    extended_twiddles: TwiddleTree,
    route: RouteV1,
    dispatch_count: usize,
    selected: []SelectedColumnV1,

    pub fn init(
        allocator: std.mem.Allocator,
        source_values: []const []const M31,
        actual_coefficients: []const []M31,
        actual_extended: []const []M31,
        transform_word_count: usize,
        extended_start: usize,
        extended_stride: usize,
        base_domain: CircleDomain,
        base_twiddles: TwiddleTree,
        extended_domain: CircleDomain,
        extended_twiddles: TwiddleTree,
    ) !GroupCaptureV1 {
        if (source_values.len == 0 or
            source_values.len != actual_coefficients.len or
            actual_coefficients.len != actual_extended.len or
            base_domain.logSize() >= extended_domain.logSize())
        {
            return error.InvalidMetalCircleLdeParityInput;
        }
        const base_len = base_domain.size();
        const extended_len = extended_domain.size();
        const plan = try routeForShape(
            transform_word_count,
            extended_start,
            extended_stride,
            extended_len,
            source_values.len,
        );
        const selected_count = selectedColumnCount(source_values.len);
        const selected = try allocator.alloc(SelectedColumnV1, selected_count);
        var initialized: usize = 0;
        errdefer {
            for (selected[0..initialized]) |*column| column.deinit(allocator);
            allocator.free(selected);
        }
        for (source_values, actual_coefficients, actual_extended, 0..) |
            source,
            coefficient,
            extended,
            column_index,
        | {
            if (source.len != base_len or coefficient.len != base_len or
                extended.len != extended_len)
            {
                return error.InvalidMetalCircleLdeParityInput;
            }
            if (!shouldCompareColumn(source_values.len, column_index)) continue;
            selected[initialized] = .{
                .group_column_index = column_index,
                // This copy must precede submission: adopted Stage101 arenas
                // use the same storage for `source` and Metal's IFFT output.
                .expected_coefficients = try allocator.dupe(M31, source),
                .actual_coefficients = coefficient,
                .actual_extended = extended,
            };
            initialized += 1;
        }
        if (initialized != selected_count)
            return error.InvalidMetalCircleLdeParityInput;
        return .{
            .group_column_count = source_values.len,
            .base_domain = base_domain,
            .extended_domain = extended_domain,
            .base_twiddles = base_twiddles,
            .extended_twiddles = extended_twiddles,
            .route = plan.route,
            .dispatch_count = plan.dispatch_count,
            .selected = selected,
        };
    }

    pub fn deinit(self: *GroupCaptureV1, allocator: std.mem.Allocator) void {
        for (self.selected) |*column| column.deinit(allocator);
        allocator.free(self.selected);
        self.* = undefined;
    }
};

pub fn enabled() bool {
    return std.process.hasEnvVarConstant(ENV_NAME);
}

pub fn shouldCompareColumn(column_count: usize, column_index: usize) bool {
    if (column_index >= column_count) return false;
    if (column_count <= 16 or column_index + 1 == column_count) return true;
    for (boundary_positions) |boundary| {
        if (column_index == boundary and boundary < column_count) return true;
    }
    return false;
}

pub fn selectedColumnCount(column_count: usize) usize {
    var count: usize = 0;
    for (0..column_count) |column_index| {
        if (shouldCompareColumn(column_count, column_index)) count += 1;
    }
    return count;
}

const RoutePlanV1 = struct {
    route: RouteV1,
    dispatch_count: usize,
};

pub fn routeForShape(
    transform_word_count: usize,
    extended_start: usize,
    extended_stride: usize,
    extended_len: usize,
    column_count: usize,
) !RoutePlanV1 {
    const abi_max_words: usize = std.math.maxInt(u32);
    if (column_count == 0 or extended_len == 0 or
        extended_stride < extended_len or extended_len > abi_max_words or
        extended_stride > abi_max_words)
    {
        return error.InvalidMetalCircleLdeParityInput;
    }
    const last_offset = std.math.mul(
        usize,
        column_count - 1,
        extended_stride,
    ) catch return error.InvalidMetalCircleLdeParityInput;
    const required = std.math.add(
        usize,
        std.math.add(usize, extended_start, last_offset) catch
            return error.InvalidMetalCircleLdeParityInput,
        extended_len,
    ) catch return error.InvalidMetalCircleLdeParityInput;
    if (required > transform_word_count)
        return error.InvalidMetalCircleLdeParityInput;
    const max_columns_per_dispatch =
        (abi_max_words - extended_len) / extended_stride + 1;
    if (max_columns_per_dispatch == 0)
        return error.InvalidMetalCircleLdeParityInput;
    const dispatch_count = (column_count - 1) / max_columns_per_dispatch + 1;
    return .{
        .route = if (dispatch_count == 1) .monolithic else .u32_rebased,
        .dispatch_count = dispatch_count,
    };
}

pub fn compareBatch(
    allocator: std.mem.Allocator,
    groups: []GroupCaptureV1,
) !ResultV1 {
    if (groups.len == 0) return error.InvalidMetalCircleLdeParityInput;
    var expected_hash = std.crypto.hash.sha2.Sha256.init(.{});
    var actual_hash = std.crypto.hash.sha2.Sha256.init(.{});
    var rebased_group_count: usize = 0;
    var dispatch_count: usize = 0;
    var selected_column_count: usize = 0;
    var coefficient_values: u64 = 0;
    var extended_values: u64 = 0;

    for (groups, 0..) |*group, group_index| {
        if (group.route == .u32_rebased) rebased_group_count += 1;
        dispatch_count = try std.math.add(
            usize,
            dispatch_count,
            group.dispatch_count,
        );
        selected_column_count = try std.math.add(
            usize,
            selected_column_count,
            group.selected.len,
        );
        for (group.selected) |*column| {
            var coefficient_batch = [_][]M31{column.expected_coefficients};
            try prover.poly.circle.poly.interpolateBuffersWithTwiddles(
                &coefficient_batch,
                group.base_domain,
                group.base_twiddles,
            );
            for (column.expected_coefficients, column.actual_coefficients, 0..) |
                expected,
                actual,
                row,
            | {
                mixEntry(&expected_hash, group_index, column.group_column_index, .coefficient, row, expected);
                mixEntry(&actual_hash, group_index, column.group_column_index, .coefficient, row, actual);
                if (!expected.eql(actual)) return .{ .mismatch = .{
                    .group_index = group_index,
                    .group_column_index = column.group_column_index,
                    .phase = .coefficient,
                    .row = row,
                    .expected = expected,
                    .actual = actual,
                } };
            }
            coefficient_values = try std.math.add(
                u64,
                coefficient_values,
                @intCast(column.expected_coefficients.len),
            );

            const expected_extended = try allocator.alloc(
                M31,
                group.extended_domain.size(),
            );
            defer allocator.free(expected_extended);
            @memcpy(
                expected_extended[0..column.expected_coefficients.len],
                column.expected_coefficients,
            );
            @memset(
                expected_extended[column.expected_coefficients.len..],
                M31.zero(),
            );
            var extended_batch = [_][]M31{expected_extended};
            try prover.poly.circle.poly.evaluateBuffersWithTwiddles(
                &extended_batch,
                group.extended_domain,
                group.extended_twiddles,
            );
            for (expected_extended, column.actual_extended, 0..) |
                expected,
                actual,
                row,
            | {
                mixEntry(&expected_hash, group_index, column.group_column_index, .extended_evaluation, row, expected);
                mixEntry(&actual_hash, group_index, column.group_column_index, .extended_evaluation, row, actual);
                if (!expected.eql(actual)) return .{ .mismatch = .{
                    .group_index = group_index,
                    .group_column_index = column.group_column_index,
                    .phase = .extended_evaluation,
                    .row = row,
                    .expected = expected,
                    .actual = actual,
                } };
            }
            extended_values = try std.math.add(
                u64,
                extended_values,
                @intCast(expected_extended.len),
            );
        }
    }

    var expected_sha256: [32]u8 = undefined;
    var actual_sha256: [32]u8 = undefined;
    expected_hash.final(&expected_sha256);
    actual_hash.final(&actual_sha256);
    const receipt = ReceiptV1{
        .group_count = groups.len,
        .rebased_group_count = rebased_group_count,
        .dispatch_count = dispatch_count,
        .selected_column_count = selected_column_count,
        .coefficient_values = coefficient_values,
        .extended_values = extended_values,
        .expected_sha256 = expected_sha256,
        .actual_sha256 = actual_sha256,
    };
    try receipt.validate();
    return .{ .exact = receipt };
}

fn mixEntry(
    hash: *std.crypto.hash.sha2.Sha256,
    group_index: usize,
    column_index: usize,
    phase: PhaseV1,
    row: usize,
    value: M31,
) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(group_index), .little);
    hash.update(&bytes);
    std.mem.writeInt(u64, &bytes, @intCast(column_index), .little);
    hash.update(&bytes);
    const phase_byte = [_]u8{@intFromEnum(phase)};
    hash.update(&phase_byte);
    std.mem.writeInt(u64, &bytes, @intCast(row), .little);
    hash.update(&bytes);
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, value.v, .little);
    hash.update(&word);
}
